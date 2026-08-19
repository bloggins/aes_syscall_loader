#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>


bool AesDecrypt(const uint8_t* ciphertext, std::size_t cipherLen, const uint8_t* key, std::size_t keyLen, const uint8_t* iv, std::size_t ivLen, std::vector<uint8_t>& plaintext);
