#include "pepenet_social.h"

bool lzma_compress_msg(const std::string& msg, std::string& out)
{
  const unsigned char* msg_ = reinterpret_cast<const unsigned char*>(msg.c_str());
  unsigned char* out_;
  std::size_t dst_len = 0;
  unsigned char* out_props;
  std::size_t out_props_size = LZMA_PROPS_SIZE;
  
  int res = LzmaCompress(out_, &dst_len, msg_, strlen(msg.c_str()) + 1,
    out_props, &out_props_size,
    5, 1 << 14, 3, 0, 2, 32, 1);
  
  out = std::string(reinterpret_cast<const char*>(out_));
  
  return res == SZ_OK;
}

bool lzma_decompress_msg(const std::string& msg, std::string& out)
{
  const unsigned char* msg_ = reinterpret_cast<const unsigned char*>(msg.c_str());
  std::size_t msg_len = strlen(msg.c_str()) + 1;
  unsigned char* out_;
  std::size_t dst_len = 0;
  unsigned char* out_props;
  std::size_t out_props_size = LZMA_PROPS_SIZE;

  int res = LzmaUncompress(out_, &dst_len, msg_, &msg_len,
    out_props, out_props_size);

  out = std::string(reinterpret_cast<const char*>(out_));

  return res == SZ_OK;
}