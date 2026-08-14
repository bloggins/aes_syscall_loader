#include "aes.h"

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// Uses the Windows CNG (bcrypt) provider for AES-256-CBC decryption. The key
// and IV come from the generated shellcode.h header; the ciphertext is the
// AES-encrypted payload embedded in the binary.

bool AesDecrypt(const uint8_t* ciphertext, std::size_t cipherLen, const uint8_t* key, std::size_t keyLen, const uint8_t* iv, std::size_t ivLen, std::vector<uint8_t>& plaintext)
{
    if (!ciphertext || !key || !iv || cipherLen == 0 || (cipherLen % 16) != 0)
        return false;

    BCRYPT_ALG_HANDLE alg  = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        goto cleanup;

    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0)
        goto cleanup;

    if (BCryptGenerateSymmetricKey(alg, &hKey, nullptr, 0, (PUCHAR)key, (ULONG)keyLen, 0) != 0)
        goto cleanup;

    {
        std::vector<uint8_t> ivCopy(iv, iv + ivLen);
        plaintext.resize(cipherLen);
        ULONG outLen = 0;

        LONG st = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)cipherLen, nullptr, ivCopy.data(), (ULONG)ivCopy.size(), plaintext.data(), (ULONG)plaintext.size(), &outLen, 0);
        if (st != 0)
            goto cleanup;
        plaintext.resize(outLen);

        // Strip PKCS#7 padding.
        if (!plaintext.empty()) {
            uint8_t pad = plaintext.back();
            if (pad >= 1 && pad <= 16 && (std::size_t)pad <= plaintext.size()) {
                bool valid = true;
                for (uint8_t i = 0; i < pad; ++i)
                    if (plaintext[plaintext.size() - 1 - i] != pad) { valid = false; break; }
                if (valid)
                    plaintext.resize(plaintext.size() - pad);
            }
        }
        ok = true;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
