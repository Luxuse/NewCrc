use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle};

// Ajoute cityhash crate dans Cargo.toml
// 

const DEFAULT_FULL_LOAD_LIMIT: u64 = 200 * 1024 * 1024;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = ".")]
    source: PathBuf,
    #[arg(short, long, default_value = "./xxHash")]
    output_dir: PathBuf,
    #[arg(short, long, default_value = "CRC.xxhash3")]
    name: String,
    #[arg(long, default_value_t = DEFAULT_FULL_LOAD_LIMIT)]
    full_load_limit: u64,
    #[arg(long, default_value_t = num_cpus::get())]
    threads: usize,
    #[arg(long, value_enum, default_value_t = HashAlgo::Xxh3)]
    algo: HashAlgo,
}

#[derive(Copy, Clone, ValueEnum)]
enum HashAlgo {
    Crc32,
    City128,
    Xxh3,
}

fn main() -> std::io::Result<()> {
    let use_interactive = std::env::args().len() == 1;

    let args = if use_interactive {
        get_interactive_args()?
    } else {
        Args::parse()
    };

    rayon::ThreadPoolBuilder::new().num_threads(args.threads).build_global().unwrap();

    fs::create_dir_all(&args.output_dir)?;
    let output_file = args.output_dir.join(&args.name);

    let files: Vec<_> = WalkDir::new(&args.source)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path() != output_file)
        .map(|e| e.path().to_path_buf())
        .collect();

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    let start = Instant::now();
    let results: Vec<_> = files
        .par_iter()
        .map(|path| {
            let res = match hash_file(path, args.full_load_limit, args.algo) {
                Ok((digest, size)) => {
                    let rel = path.strip_prefix(&args.source).unwrap_or(path);
                    (format!("{digest} *..\\{}\n", rel.display()), size, 0)
                }
                Err(e) => (format!("[ERROR] {}: {}\n", path.display(), e), 0, 1),
            };
            pb.inc(1);
            res
        })
        .collect();
    pb.finish();

    let mut out = File::create(&output_file)?;
    let (mut total_bytes, mut total_errors) = (0u64, 0u64);
    for (line, size, err) in &results {
        out.write_all(line.as_bytes())?;
        total_bytes += *size;
        total_errors += *err as u64;
    }

    let elapsed = start.elapsed().as_secs_f64();
    println!("\nDone! Hashes saved to: {}", output_file.display());
    println!("=== Statistiques ===");
    println!("Fichiers traités    : {}", files.len());
    println!("Erreurs             : {}", total_errors);
    println!("Volume total        : {}", human_readable(total_bytes));
    println!("Temps écoulé        : {:.2} s", elapsed);
    println!("Débit moyen         : {}/s", human_readable((total_bytes as f64 / elapsed) as u64));

    println!("Appuyez sur Entrée pour quitter...");
    let mut pause = String::new();
    io::stdin().read_line(&mut pause).unwrap();

    Ok(())
}

fn get_interactive_args() -> io::Result<Args> {
    println!("=== Générateur de hash ===");
    println!("Choix de l'algorithme :");
    println!("  1. CRC32");
    println!("  2. City128");
    println!("  3. XXH3 (défaut)");
    print!("Votre choix [1-3] : ");
    io::stdout().flush()?;

    let mut choice_input = String::new();
    io::stdin().read_line(&mut choice_input)?;
    let (algo, filename) = match choice_input.trim() {
        "1" => (HashAlgo::Crc32, "CRC.crc32"),
        "2" => (HashAlgo::City128, "CRC.city128"),
        _ => (HashAlgo::Xxh3, "CRC.xxhash3"),
    };

    Ok(Args {
        source: PathBuf::from("."),
        output_dir: PathBuf::from("./NewCrc"),
        name: filename.to_string(),
        full_load_limit: u64::MAX,
        threads: num_cpus::get(),
        algo,
    })
}

fn hash_file(path: &Path, full_load_limit: u64, algo: HashAlgo) -> io::Result<(String, u64)> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    let mut file = File::open(path)?;

    if size <= full_load_limit {
        let mut buf = Vec::with_capacity(size as usize);
        file.read_to_end(&mut buf)?;
        let digest = match algo {
            HashAlgo::Crc32 => format!("{:08x}", crc32fast::hash(&buf)),
            HashAlgo::City128 => format!("{:032x}", cityhash::city128(&buf)),
            HashAlgo::Xxh3 => format!("{:016x}", xxhash_rust::xxh3::xxh3_64(&buf)),
        };
        Ok((digest, size))
    } else {
        let mut hasher_crc32 = crc32fast::Hasher::new();
        let mut buf = [0u8; 1024 * 1024];
        let mut city_hash_val = cityhash::CityHasher128::new();
        let mut hasher_xxh3 = xxhash_rust::xxh3::Xxh3::new();

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            match algo {
                HashAlgo::Crc32 => hasher_crc32.update(&buf[..n]),
                HashAlgo::City128 => city_hash_val.update(&buf[..n]),
                HashAlgo::Xxh3 => hasher_xxh3.update(&buf[..n]),
            }
        }

        let digest = match algo {
            HashAlgo::Crc32 => format!("{:08x}", hasher_crc32.finalize()),
            HashAlgo::City128 => format!("{:032x}", city_hash_val.digest()),
            HashAlgo::Xxh3 => format!("{:016x}", hasher_xxh3.digest()),
        };
        Ok((digest, size))
    }
}

fn human_readable(num_bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut i = 0;
    let mut n = num_bytes as f64;
    while n >= 1024.0 && i < units.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    format!("{:.2} {}", n, units[i])
}
