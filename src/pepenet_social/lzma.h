//credit to: https://gist.github.com/Treeki/f431a2ff44aff984590a97a5c09f6f28
#pragma once

#include "lzma/C/LzmaEnc.h"
#include "lzma/C/LzmaDec.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <memory>

std::unique_ptr<uint8_t[]> lzmaCompress(const uint8_t* input, uint32_t inputSize, uint32_t* outputSize);
std::unique_ptr<uint8_t[]> lzmaDecompress(const uint8_t* input, uint32_t inputSize, uint32_t* outputSize);
void hexdump(const uint8_t* buf, int size);
void testIt(const uint8_t* input, int size);
void testIt(const char* string);
