# NewCrc

## ia use in code cause C++ pain 

This is a Win32 GUI application for verifying file integrity using CRC32 or XXH3 hashes.

### Usage

1.  Place the executable (NewCrc.exe) in the directory with the files to check.
2.  Ensure a hash list file (`CRC.crc32` or `CRC.xxhash3`) is present.

### Command Line / Batch Mode

To start the verification automatically on launch, use the `-v` flag:

```bash
NewCrc.exe -v



***


```compile
g++ -std=c++17 -O3 -static main.cpp xxhash.c -lole32 -lcomctl32 -lriched20 -municode -Wl,--subsystem,windows -o NewCrc.exe

and stripe the exe
