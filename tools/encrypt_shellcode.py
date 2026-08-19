#!/usr/bin/env python3
"""AES-256-CBC encrypt a raw shellcode file into a C/C++ header.

Usage:
    python3 encrypt_shellcode.py <shellcode.bin> <output.h> [key_hex] [iv_hex]

    key_hex: 64 hex chars (32 bytes). Omit to generate a random key.
    iv_hex:  32 hex chars (16 bytes). Omit to generate a random IV.

Requires: pip install pycryptodome
"""
import sys
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def c_array(name, data, per_line=16):
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    body = "\n".join(lines)
    return f"static const uint8_t {name}[] = {{\n{body}\n}};"


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    sc_path = sys.argv[1]
    out_path = sys.argv[2]

    with open(sc_path, "rb") as f:
        data = f.read()

    if len(sys.argv) > 3 and sys.argv[3]:
        key = bytes.fromhex(sys.argv[3])
    else:
        key = secrets.token_bytes(32)

    if len(sys.argv) > 4 and sys.argv[4]:
        iv = bytes.fromhex(sys.argv[4])
    else:
        iv = secrets.token_bytes(16)

    if len(key) != 32:
        print("error: key must be 32 bytes (64 hex chars)")
        sys.exit(1)
    if len(iv) != 16:
        print("error: iv must be 16 bytes (32 hex chars)")
        sys.exit(1)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    with open(out_path, "w") as f:
        f.write("#pragma once\n")
        f.write("#include <cstdint>\n\n")
        f.write(f"// original shellcode size: {len(data)} bytes\n")
        f.write(f"// ciphertext size:        {len(ciphertext)} bytes\n\n")
        f.write(c_array("encrypted_shellcode", ciphertext) + "\n\n")
        f.write(c_array("aes_key", key, per_line=16) + "\n\n")
        f.write(c_array("aes_iv", iv, per_line=16) + "\n")

    print(f"[+] wrote {out_path}")
    print(f"[+] plaintext  : {len(data)} bytes")
    print(f"[+] ciphertext : {len(ciphertext)} bytes")
    print(f"[+] key (hex)  : {key.hex()}")
    print(f"[+] iv  (hex)  : {iv.hex()}")


if __name__ == "__main__":
    main()
