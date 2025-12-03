use cityhash::city_hash_128;
use clap::{Parser, ValueEnum};
use crc32c::crc32c; // Pour CRC32C (Castagnoli)
use crc32fast::Hasher as Crc32Hasher;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use walkdir::WalkDir;
use xxhash_rust::xxh3::Xxh3;

// Imports pour les nouveaux algorithmes
use blake2::{Blake2b512, Blake2s256};
use sha2::{Digest, Sha256, Sha512};
use once_cell::sync::Lazy;

// La taille du tampon pour le mode streaming (1 MiB)
const BUFFER_SIZE: usize = 1024 * 1024;
const DEFAULT_FULL_LOAD_LIMIT: u64 = 200 * 1024 * 1024;

// CRC32C (Castagnoli) lookup table (reflected polynomial 0x82F63B78)
static CRC32C_TABLE: Lazy<[u32; 256]> = Lazy::new(|| {
    let poly: u32 = 0x82F63B78u32;
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut c = i;
        for _ in 0..8 {
            if (c & 1) != 0 {
                c = poly ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        table[i as usize] = c;
    }
    table
});

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = ".")]
    source: PathBuf,
    #[arg(short, long, default_value = "./Hashes")]
    output_dir: PathBuf,
    #[arg(short, long, default_value = "checksums.txt")]
    name: String,
    // Limite au-dessus de laquelle on passe en mode streaming pour économiser la RAM
    #[arg(long, default_value_t = DEFAULT_FULL_LOAD_LIMIT)]
    full_load_limit: u64,
    #[arg(long, default_value_t = num_cpus::get())]
    threads: usize,
    #[arg(long, value_enum, default_value_t = HashAlgo::Xxh3)]
    algo: HashAlgo,
}

#[derive(Copy, Clone, ValueEnum)]
enum HashAlgo {
    // Hashes légers et rapides (non-cryptographiques)
    Crc32,
    Crc32c,
    City128,
    Xxh3,
    // Hashes cryptographiques (plus lents, plus sécurisés)
    Sha256,
    Sha512,
    Blake2b,
    Blake2s,
}

fn main() -> std::io::Result<()> {
    let use_interactive = std::env::args().len() == 1;

    let args = if use_interactive {
        get_interactive_args()?
    } else {
        Args::parse()
    };

    rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()
        .unwrap();

    fs::create_dir_all(&args.output_dir)?;
    let output_file = args.output_dir.join(&args.name);

    let files: Vec<_> = WalkDir::new(&args.source)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        // Filtrer le fichier de sortie lui-même
        .filter(|e| {
            e.path()
                .canonicalize()
                .unwrap_or_else(|_| e.path().to_path_buf())
                != output_file
                    .canonicalize()
                    .unwrap_or_else(|_| output_file.to_path_buf())
        })
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
                    // Calcul du chemin relatif
                    let rel = path.strip_prefix(&args.source).unwrap_or(path);
                    // Format standard du fichier de checksum (digest *chemin)
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
    println!("Fichiers traités     : {}", files.len());
    println!("Erreurs              : {}", total_errors);
    println!("Volume total         : {}", human_readable(total_bytes));
    println!("Temps écoulé         : {:.2} s", elapsed);
    println!(
        "Débit moyen          : {}/s",
        human_readable((total_bytes as f64 / elapsed) as u64)
    );

    println!("Appuyez sur Entrée pour quitter...");
    let mut pause = String::new();
    io::stdin().read_line(&mut pause).unwrap();

    Ok(())
}

// Fonction pour hacher un fichier
fn hash_file(path: &Path, full_load_limit: u64, algo: HashAlgo) -> io::Result<(String, u64)> {
    let meta = fs::metadata(path)?;
    let size = meta.len();
    let mut file = File::open(path)?;

    // --------------------------------------------------------------------------------
    // CAS 1: PETIT FICHIER (Charge complète en mémoire pour une performance maximale)
    // --------------------------------------------------------------------------------
    if size <= full_load_limit {
        let mut buf = Vec::with_capacity(size as usize);
        file.read_to_end(&mut buf)?;

        let digest = match algo {
            HashAlgo::Crc32 => format!("{:08x}", crc32fast::hash(&buf)),
            HashAlgo::Crc32c => format!("{:08x}", crc32c(&buf)),
            HashAlgo::City128 => format!("{:032x}", city_hash_128(&buf)),
            HashAlgo::Xxh3 => format!("{:016x}", xxhash_rust::xxh3::xxh3_64(&buf)),
            HashAlgo::Sha256 => format!("{:x}", Sha256::digest(&buf)),
            HashAlgo::Sha512 => format!("{:x}", Sha512::digest(&buf)),
            HashAlgo::Blake2b => format!("{:x}", Blake2b512::digest(&buf)),
            HashAlgo::Blake2s => format!("{:x}", Blake2s256::digest(&buf)),
        };
        Ok((digest, size))
    }
    // --------------------------------------------------------------------------------
    // CAS 2: GRAND FICHIER (Mode streaming pour économiser la RAM)
    // --------------------------------------------------------------------------------
    else {
        // CityHash ne supporte pas le mode streaming avec le crate actuel,
        // nous devons donc charger le fichier en entier, ce qui est contraire
        // à l'objectif de faible RAM. On retourne une erreur pour forcer l'utilisateur
        // à augmenter la limite ou choisir un autre algo.
        if let HashAlgo::City128 = algo {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "City128 ne supporte pas le streaming. Veuillez augmenter --full-load-limit ou choisir un autre algo.",
            ));
        }

        let mut hasher: Box<dyn HashingStream> = match algo {
            HashAlgo::Crc32 => Box::new(Crc32Stream::new()),
            HashAlgo::Crc32c => Box::new(Crc32cStream::new()),
            HashAlgo::Xxh3 => Box::new(Xxh3Stream::new()),
            HashAlgo::Sha256 => Box::new(CryptoStream::<Sha256>::new()),
            HashAlgo::Sha512 => Box::new(CryptoStream::<Sha512>::new()),
            HashAlgo::Blake2b => Box::new(CryptoStream::<Blake2b512>::new()),
            HashAlgo::Blake2s => Box::new(CryptoStream::<Blake2s256>::new()),
            // City128 est géré ci-dessus
            _ => unreachable!(),
        };

        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let digest = hasher.finalize();
        Ok((digest, size))
    }
}

// --------------------------------------------------------------------------------
// TRAITS ET STRUCTURES POUR LE STREAMING (lecture par blocs)
// --------------------------------------------------------------------------------

trait HashingStream {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> String;
}

// Implémentation générique pour les hashes cryptographiques (SHA, Blake)
struct CryptoStream<T: Digest + Send + 'static> {
    hasher: T,
}

impl<T: Digest + Send + 'static> CryptoStream<T> {
    fn new() -> Self {
        CryptoStream { hasher: T::new() }
    }
}

impl<T: Digest + Send + 'static> HashingStream for CryptoStream<T> {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    fn finalize(&mut self) -> String {
        // Swap out the current hasher with a fresh one and finalize the old
        // instance. This avoids requiring the `FixedOutputReset` trait.
        let hasher = std::mem::replace(&mut self.hasher, T::new());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// Implémentation pour CRC32
struct Crc32Stream {
    hasher: Crc32Hasher,
}

impl Crc32Stream {
    fn new() -> Self {
        Crc32Stream {
            hasher: Crc32Hasher::new(),
        }
    }
}

impl HashingStream for Crc32Stream {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    fn finalize(&mut self) -> String {
        format!("{:08x}", self.hasher.clone().finalize())
    }
}

// Implémentation pour CRC32C (streaming via table-driven algorithm)
struct Crc32cStream {
    digest: u32,
}

impl Crc32cStream {
    fn new() -> Self {
        // Start with all-ones as is standard for CRC-32C (we XOR at the end)
        Crc32cStream { digest: 0xFFFF_FFFFu32 }
    }
}

impl HashingStream for Crc32cStream {
    fn update(&mut self, data: &[u8]) {
        let table = &*CRC32C_TABLE;
        let mut crc = self.digest;
        for &b in data {
            crc = (crc >> 8) ^ table[((crc as u8) ^ b) as usize];
        }
        self.digest = crc;
    }
    fn finalize(&mut self) -> String {
        let final_crc = self.digest ^ 0xFFFF_FFFFu32;
        format!("{:08x}", final_crc)
    }
}

// Implémentation pour XXH3
struct Xxh3Stream {
    hasher: Xxh3,
}

impl Xxh3Stream {
    fn new() -> Self {
        Xxh3Stream {
            hasher: Xxh3::new(),
        }
    }
}

impl HashingStream for Xxh3Stream {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
    fn finalize(&mut self) -> String {
        format!("{:016x}", self.hasher.digest())
    }
}

// --------------------------------------------------------------------------------
// UTILS
// --------------------------------------------------------------------------------

fn get_interactive_args() -> io::Result<Args> {
    println!("=== NewCrc gen v2 ===");
    println!("Choix de l'algorithme :");
    println!("  1. CRC32");
    println!("  2. CRC32C (Castagnoli)");
    println!("  3. City128 (Attention: Ne supporte pas le streaming pour gros fichiers)");
    println!("  4. XXH3 (défaut)");
    println!("  5. SHA256");
    println!("  6. SHA512");
    println!("  7. Blake2b (512-bit)");
    println!("  8. Blake2s (256-bit)");
    print!("Votre choix [1-8] : ");
    io::stdout().flush()?;

    let mut choice_input = String::new();
    io::stdin().read_line(&mut choice_input)?;

    let (algo, filename) = match choice_input.trim() {
        "1" => (HashAlgo::Crc32, "CRC.crc32"),
        "2" => (HashAlgo::Crc32c, "CRC.crc32c"),
        "3" => (HashAlgo::City128, "CRC.city128"),
        "5" => (HashAlgo::Sha256, "CRC.sha256"),
        "6" => (HashAlgo::Sha512, "CRC.sha512"),
        "7" => (HashAlgo::Blake2b, "CRC.blake2b"),
        "8" => (HashAlgo::Blake2s, "CRC.blake2s"),
        _ => (HashAlgo::Xxh3, "CRC.xxhash3"), // Défaut Xxh3
    };

    Ok(Args {
        source: PathBuf::from("."),
        output_dir: PathBuf::from("./NewCrc"),
        name: filename.to_string(),
        full_load_limit: DEFAULT_FULL_LOAD_LIMIT,
        threads: num_cpus::get(),
        algo,
    })
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
