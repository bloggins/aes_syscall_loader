msfvenom -p windows/x64/messagebox TEXT="hello" -f raw -o payload.bin

python3 encrypt_shellcode.py payload.bin shellcode.h   

x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o loader.exe main.cpp syscalls.cpp aes.cpp -lbcrypt -s
