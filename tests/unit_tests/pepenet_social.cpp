// Copyright (c) 2023, pepenet
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
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "../contrib/epee/include/string_tools.h"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

boost::optional<std::string> social_err;

TEST(pepenet_social_functions, lzma_compress_decompress)
{
  std::string msg = "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS ANDHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDE";
  std::string out;
  ASSERT_TRUE(pepenet_social::lzma_compress_msg(msg, out));
  ASSERT_TRUE(out.size() < msg.size());

  std::string msg_decopressed;
  ASSERT_TRUE(pepenet_social::lzma_decompress_msg(out, msg_decopressed));
  ASSERT_TRUE(msg_decopressed == msg);
}

TEST(pepenet_social_functions, sing_verify_msg)
{
  //generate keys
  std::string hex_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  crypto::secret_key sk;
  ASSERT_TRUE(pepenet_social::secret_key_from_seed(hex_seed, sk));
  crypto::public_key pk;
  ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));
  //sign msg
  std::string msg = "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS ANDHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDE";
  crypto::signature sig;
  ASSERT_TRUE(pepenet_social::sign_msg(msg, sig, pk, sk));
  //check msg
  ASSERT_TRUE(pepenet_social::check_msg_sig(msg, sig, pk));
}

TEST(pepenet_social_functions, to_bytes_from_bytes)
{
  /*
  bool to_bytes(const crypto::signature& sig, bytes& b);
  bool from_bytes(crypto::signature& sig, const bytes& b);
  bool to_bytes(const crypto::hash& hash, bytes& b);
  bool from_bytes(crypto::hash& hash, const bytes& b);
  bool to_bytes(const crypto::public_key& pk, bytes& b);
  bool from_bytes(crypto::public_key& pk, const bytes& b);
  */
  //make a sig, tx_ref and pk
  std::string hex_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  crypto::secret_key sk;
  ASSERT_TRUE(pepenet_social::secret_key_from_seed(hex_seed, sk));
  crypto::public_key pk;
  ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));
  //sign msg
  std::string msg = "THIS SOFTWARE IS PROVIDED BYBY THE COPYRIGHT";
  crypto::hash tx_ref = crypto::cn_fast_hash(msg.data(), msg.size());
  crypto::signature sig;
  ASSERT_TRUE(pepenet_social::sign_msg(msg, sig, pk, sk));
  //check serialization
  pepenet_social::bytes tx_ref_bytes, pk_bytes, sig_bytes;
  crypto::hash tx_ref_out;
  crypto::public_key pk_out;
  crypto::signature sig_out;
  
  ASSERT_TRUE(pepenet_social::to_bytes(tx_ref, tx_ref_bytes));
  ASSERT_TRUE(pepenet_social::from_bytes(tx_ref_out, tx_ref_bytes));
  ASSERT_EQ(tx_ref, tx_ref_out);

  ASSERT_TRUE(pepenet_social::to_bytes(pk, pk_bytes));
  ASSERT_TRUE(pepenet_social::from_bytes(pk_out, pk_bytes));
  ASSERT_EQ(pk, pk_out);

  ASSERT_TRUE(pepenet_social::to_bytes(sig, sig_bytes));
  ASSERT_TRUE(pepenet_social::from_bytes(sig_out, sig_bytes));
  ASSERT_EQ(sig, sig_out);
}