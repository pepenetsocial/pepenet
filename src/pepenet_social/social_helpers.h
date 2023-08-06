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

#pragma once

#include "social_defines.h"
#include "lzma.h"
#include "crypto/crypto.h"
#include "../contrib/epee/include/hex.h"
#include "../contrib/epee/include/misc_log_ex.h"
#include "../contrib/epee/include/string_tools.h"

namespace pepenet_social {

  typedef std::string bytes;

  struct ibool
  {
    bool b;
    boost::optional<std::string> info;
  };

  bool lzma_compress_msg(const std::string& msg, std::string& out);
  bool lzma_decompress_msg(const std::string& msg, std::string& out);
  
  bool secret_key_from_seed(const std::string& sk_seed, crypto::secret_key& sk);
  bool sign_msg(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk, const crypto::secret_key& sk);
  bool check_msg_sig(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk);

  bool to_bytes(const crypto::signature& sig, bytes& b);
  
  bool from_bytes(crypto::signature& sig, const bytes& b);
  bool to_bytes(const crypto::hash& hash, bytes& b);
  bool from_bytes(crypto::hash& hash, const bytes& b);
  bool to_bytes(const crypto::public_key& pk, bytes& b);
  bool from_bytes(crypto::public_key& pk, const bytes& b);

  boost::optional<bytes> get_optional_bytes(const bytes& b);
  boost::optional<std::string> get_optional_string(const std::string& s);
}