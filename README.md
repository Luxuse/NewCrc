# NewCrc

## Purpose

NewCrc is a Win32 GUI application for verifying file integrity using **CRC32**, **XXH3**, or **City128** hashes. 

note ia use in code 
## Usage

1. Place `NewCrc.exe` in the folder containing the files to check.  
2. Ensure a hash list file is present in the same folder:
   - `CRC.crc32`
   - `CRC.xxhash3`
   - `CRC.city128`

### compile

compile

g++ -std=c++20 -Oz -static main.cpp xxhash.c city.cc -lole32 -lcomctl32 -lriched20 -municode -Wl,--subsystem,windows -o NewCrc.exe

strip NewCrc.exe


### Command Line / Batch Mode

Start verification automatically on launch using the `-v` flag:

bash
NewCrc.exe -v
