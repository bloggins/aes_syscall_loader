#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

// AES-256-CBC decryption with PKCS#7 padding removal.
// Returns false on any error (bad size, provider failure, bad decrypt).
bool AesDecrypt(const uint8_t* ciphertext, std::size_t cipherLen, const uint8_t* key, std::size_t keyLen, const uint8_t* iv, std::size_t ivLen, std::vector<uint8_t>& plaintext);
