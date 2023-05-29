#include "LzmaLib.h"
#include "../crypto/crypto.h"
#include <iostream>

bool lzma_compress_msg(const std::string &msg, std::string &out);
bool lzma_decompress_msg(const std::string &msg, std::string &out);
bool parse_hex_secret_key(const std::string& hex_sk, crypto::secret_key &sk);
crypto::public_key get_public_key(const crypto::secret_key &sk);
bool sign_msg(const std::string &msg, crypto::signature &sig);
