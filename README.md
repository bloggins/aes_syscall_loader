msfvenom -p windows/x64/messagebox TEXT="hello" -f raw -o payload.bin

python3 tools\encrypt_shellcode.py payload.bin src\shellcode.h   

x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o loader.exe src\main.cpp src\syscalls.cpp src\aes.cpp -lbcrypt -s

