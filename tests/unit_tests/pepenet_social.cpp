// Copyright (c) 2023, pepenet
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include "pepenet_social/pepenet_social.h"

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

TEST(pepenet_social, lzma_bytes_test)
{
  testIt("a");
  testIt("here is a cool string");
  testIt("here's something that should compress pretty well: abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef");
}

TEST(pepenet_social, lzma_bytes_eq_test)
{
  const char msg[] = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef";
  GTEST_COUT << "msg: " << std::string(msg) << std::endl;
  char* out;
  const uint8_t* msg_ = (const uint8_t*)msg;
  std::size_t msg_len = strlen(msg);
  uint32_t compressed_size;
  auto compressedBlob = lzmaCompress(msg_, msg_len, &compressed_size);
  out = (char*)(compressedBlob.get());
  GTEST_COUT << "comp: " << std::string(out) << std::endl;
  GTEST_COUT << "comp_strlen: " << std::string(out).size() << std::endl;
  GTEST_COUT << "compressed size(ret. val): " << compressed_size << std::endl;
  //decompress
  uint32_t decompressed_size;
  auto decompressedBlob = lzmaDecompress((const uint8_t*)out, compressed_size, &decompressed_size);
  
  char* decomp_out = (char*)(decompressedBlob.get());
  GTEST_COUT << "decomp:" << std::string(decomp_out) << std::endl;

  std::string decomp_msg = std::string(decomp_out);
  decomp_msg.pop_back();
  ASSERT_TRUE(std::string(msg) == decomp_msg);
}

TEST(pepenet_social, lzma_bytes_eq_test_with_strings)
{
  std::string input_message = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef";
  const char* msg = input_message.c_str();
  GTEST_COUT << "msg: " << std::string(msg) << std::endl;
  char* out;
  const uint8_t* msg_ = (const uint8_t*)msg;
  std::size_t msg_len = strlen(msg);
  uint32_t compressed_size;
  auto compressedBlob = lzmaCompress(msg_, msg_len, &compressed_size);
  out = (char*)(compressedBlob.get());
  GTEST_COUT << "comp: " << std::string(out, compressed_size) << std::endl;
  GTEST_COUT << "comp_strlen: " << std::string(out, compressed_size).size() << std::endl;
  GTEST_COUT << "compressed size(ret. val): " << compressed_size << std::endl;
  //convert to string
  std::string converted_compressed(out, compressed_size);
  //decompress
  uint32_t decompressed_size;
  auto decompressedBlob = lzmaDecompress((const uint8_t*)converted_compressed.c_str(), converted_compressed.size(), &decompressed_size);

  char* decomp_out = (char*)(decompressedBlob.get());
  GTEST_COUT << "decomp:" << std::string(decomp_out) << std::endl;

  std::string decomp_msg = std::string(decomp_out, decompressed_size);
  ASSERT_TRUE(std::string(msg) == decomp_msg);
}

TEST(pepenet_social, lzma_compress_decompress)
{
  std::string msg = "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS ANDHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDE";
  GTEST_COUT << "msg: " << msg << std::endl;
  std::string out;
  ASSERT_TRUE(lzma_compress_msg(msg, out));
  ASSERT_TRUE(out.size() < msg.size());
  GTEST_COUT << "compressed: " << out << std::endl;

  std::string msg_decopressed;
  ASSERT_TRUE(lzma_decompress_msg(out, msg_decopressed));
  GTEST_COUT << "decompressed: " << msg_decopressed << std::endl;
  ASSERT_TRUE(msg_decopressed == msg);
}