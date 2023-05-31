#include "lzma.h"
#include "crypto/crypto.h"
#include "../contrib/epee/include/hex.h"
#include "../contrib/epee/include/misc_log_ex.h"
#include <iostream>
#include <vector>

bool lzma_compress_msg(const std::string& msg, std::string& out);
bool lzma_decompress_msg(const std::string& msg, std::string& out);
bool secret_key_from_seed(const std::string& sk_seed, crypto::secret_key &sk);
//use crypto::secret_key_to_public_key
bool sign_msg(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk, const crypto::secret_key& sk);
bool check_msg_sig(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk);