# NewCrc


## Purpose

NewCrc is a Win32 GUI application for verifying file integrity using **CRC32**, **XXH3**, or **City128**, or **blake2s** and others hashes. 

note : ia use in code 
## Roadmap

add SHA512 support fix GUI block thread and add other hash, fix crc32c

## Usage

1. Place `NewCrc.exe` in the folder containing the files to check.  
2. Ensure a hash list file is present in the same folder:
   - `CRC.crc32`
   - `CRC.xxhash3`
   - `CRC.city128`
   - `CRC.crc32c`
   - `CRC.Blake2b`
....
### compile

compile

$ g++ -std=c++20 -Oz -msse4.2 -static     main.cpp xxhash.c city.cc blake2s-ref.c blake2b-ref.c     -I.     -lole32 -lcomctl32 -lriched20 -municode -Wl,--subsystem,windows     -o NewCrc.exe


$ strip NewCrc.exe

### Command Line / Batch Mode

Start verification automatically on launch using the `-v` flag:

bash
NewCrc.exe -v
