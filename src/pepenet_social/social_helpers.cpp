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

#include "social_helpers.h"

namespace pepenet_social {

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

  bool to_bytes(const crypto::signature& sig, bytes& b)
  {
    b = bytes(sig.c.data, 32) + bytes(sig.r.data, 32);
    return true;
  }
  bool from_bytes(crypto::signature& sig, const bytes& b)
  {
    if (b.size() != 64)
    {
      return false;
    }
    try
    {
      std::memcpy(&sig.c.data, b.data(), 32);
      std::memcpy(&sig.r.data, b.data() + 32, 32);
    }
    catch (const std::exception& e)
    {
      return false;
    }
    return true;
  }
  bool to_bytes(const crypto::hash& hash, bytes& b)
  {
    b = bytes(hash.data, 32);
    return true;
  }
  bool from_bytes(crypto::hash& hash, const bytes& b)
  {
    if (b.size() != 32)
    {
      return false;
    }
    try
    {
      std::memcpy(&hash.data, b.data(), 32);
    }
    catch (const std::exception& e)
    {
      return false;
    }
    return true;
  }
  bool to_bytes(const crypto::public_key& pk, bytes& b)
  {
    b = bytes(pk.data, 32);
    return true;
  }
  bool from_bytes(crypto::public_key& pk, const bytes& b)
  {
    if (b.size() != 32)
    {
      return false;
    }
    try
    {
      std::memcpy(&pk.data, b.data(), 32);
    }
    catch (const std::exception& e)
    {
      return false;
    }
    return true;
  }

  boost::optional<bytes> get_optional_bytes(const bytes& b)
  {
    return b.empty() ? boost::optional<std::string>() : b;
  }

  boost::optional<std::string> get_optional_string(const std::string& s)
  {
    return s.empty() ? boost::optional<std::string>() : s;
  }

}