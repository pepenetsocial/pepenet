#include "pepenet_social.h"

bool lzma_compress_msg(const std::string& msg, std::string& out)
{
  const uint8_t* msg_ = (const uint8_t*)msg.c_str();
  std::size_t msg_len = strlen(msg.c_str());
  uint32_t compressed_size;
  auto compressedBlob = lzmaCompress(msg_, msg_len, &compressed_size);
  if (compressedBlob)
    out = std::string(reinterpret_cast<const char*>(compressedBlob.get()), compressed_size);
  return (bool)compressedBlob;
}

bool lzma_decompress_msg(const std::string& msg, std::string& out)
{
  const uint8_t* msg_ = (const uint8_t*)msg.c_str();
  std::size_t msg_len = strlen(msg.c_str());
  uint32_t decompressed_size;
  auto decompressedBlob = lzmaDecompress(msg_, msg_len, &decompressed_size);
  if (decompressedBlob)
    out = std::string(reinterpret_cast<const char*>(decompressedBlob.get()), decompressed_size);
  return (bool)decompressedBlob;
}