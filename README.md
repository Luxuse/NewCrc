g++ -std=c++17 -O2 -static main.cpp xxhash.c -lole32 -lcomctl32 -lriched20 -municode -Wl,--subsystem,windows -o NewCrc.exe
