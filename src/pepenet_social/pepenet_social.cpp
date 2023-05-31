#include "pepenet_social.h"

bool lzma_compress_msg(const std::string& msg, std::string& out)
{
  const uint8_t* msg_ = (const uint8_t*)msg.c_str();
  std::size_t msg_len = strlen(msg.c_str());
  uint32_t compressed_size;
  auto compressedBlob = lzmaCompress(msg_, msg_len, &compressed_size);
  if (compressedBlob)
    out = std::string((char*)(compressedBlob.get()), compressed_size);
  return (bool)compressedBlob;
}

bool lzma_decompress_msg(const std::string& msg, std::string& out)
{
  const uint8_t* msg_ = (const uint8_t*)msg.c_str();
  std::size_t msg_len = msg.size();
  uint32_t decompressed_size;
  auto decompressedBlob = lzmaDecompress(msg_, msg_len, &decompressed_size);
  if (decompressedBlob)
    out = std::string((char*)(decompressedBlob.get()), decompressed_size);
  return (bool)decompressedBlob;
}

bool secret_key_from_seed(const std::string& sk_seed, crypto::secret_key& sk)
{
  try
  {
    crypto::hash_to_scalar(sk_seed.data(), sk_seed.size(), sk);
  }
  catch (const std::exception& ex)
  {
    LOG_ERROR("Exception at [secret_key_from_seed], what=" << ex.what());
    return false;
  }
  return true;
}

bool sign_msg(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk, const crypto::secret_key& sk)
{
  crypto::hash prefix_hash;
  try
  {
    crypto::cn_fast_hash(msg.data(), msg.size(), prefix_hash);
    crypto::generate_signature(prefix_hash, pk, sk, sig);
  }
  catch (const std::exception& ex)
  {
    LOG_ERROR("Exception at [sign_msg], what=" << ex.what());
    return false;
  }
  return true;
}

bool check_msg_sig(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk)
{
  crypto::hash prefix_hash;
  bool r;
  try
  {
    crypto::cn_fast_hash(msg.data(), msg.size(), prefix_hash);
    r = crypto::check_signature(prefix_hash, pk, sig);
  }
  catch (const std::exception& ex)
  {
    LOG_ERROR("Exception at [sign_msg], what=" << ex.what());
    return false;
  }
  return r;
}