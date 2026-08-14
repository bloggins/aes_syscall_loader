msfvenom -p windows/x64/messagebox TEXT="hello" -f raw -o payload.bin

python3 encrypt_shellcode.py payload.bin shellcode.h   

x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o loader.exe main.cpp syscalls.cpp aes.cpp -lbcrypt -s


aes_syscall_loader/
├── loader.exe                  # x64 Windows executable (MinGW statically linked, 216 KB)
├── src/
│   ├── main.cpp                # Loader orchestration: Decryption → RW allocation → Write → RX → Thread execution
│   ├── syscalls.h / .cpp       # Dynamic SSN resolution + direct syscall stubs + wrapper functions
│   ├── aes.h / .cpp            # BCrypt AES-256-CBC decryption + PKCS#7 unpadding
│   └── shellcode.h             # Generated encrypted payload + Key/IV (randomly generated)
└── tools/
├── demo_shellcode.asm      # Demo payload: PEB → kernel32 → djb2 hash resolution → MessageBoxA
├── demo_shellcode.bin      # Assembly output (340-byte raw shellcode)
└── encrypt_shellcode.py    # Generator: Payload → AES-encrypted header file
