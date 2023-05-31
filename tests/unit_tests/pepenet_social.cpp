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

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

TEST(pepenet_social, lzma_compress_decompress)
{
  std::string msg = "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS ANDHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDE";
  std::string out;
  ASSERT_TRUE(lzma_compress_msg(msg, out));
  ASSERT_TRUE(out.size() < msg.size());

  std::string msg_decopressed;
  ASSERT_TRUE(lzma_decompress_msg(out, msg_decopressed));
  ASSERT_TRUE(msg_decopressed == msg);
}

TEST(pepenet_social, sing_verify_msg_1)
{
  //generate keys
  std::string hex_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  crypto::secret_key sk;
  ASSERT_TRUE(secret_key_from_seed(hex_seed, sk));
  crypto::public_key pk;
  ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));
  //sign msg
  std::string msg = "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS ANDHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDE";
  crypto::signature sig;
  ASSERT_TRUE(sign_msg(msg, sig, pk, sk));
  //check msg
  ASSERT_TRUE(check_msg_sig(msg, sig, pk));
}

TEST(pepenet_social, pep_to_from_extra)
{
  //fake transfer_main arguments
  std::string pep = "Long live pepent. Freedom to everyone!!!";
  std::string pseudonym = "Mr. pepe";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  crypto::hash tx_ref = crypto::cn_fast_hash(pseudonym.data(), pseudonym.size());
  //add to tx extra
  cryptonote::transaction tx;
  std::string lzma_pep;
  ASSERT_TRUE(lzma_compress_msg(pep, lzma_pep));
  //get keys
  crypto::public_key pk;
  crypto::secret_key sk;
  ASSERT_TRUE(secret_key_from_seed(sk_seed, sk));
  ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));
  crypto::signature full_pep_sig;
  //contruct full content for signing
  std::string full_pep = pep + pseudonym + std::string(tx_ref.data, 32) + std::string(pk.data, 32);
  sign_msg(full_pep, full_pep_sig, pk, sk);
  //add all fields to extra
  ASSERT_TRUE(cryptonote::add_lzma_pep_to_tx_extra(tx.extra, lzma_pep));
  ASSERT_TRUE(cryptonote::add_pseudonym_to_tx_extra(tx.extra, pseudonym));
  ASSERT_TRUE(cryptonote::add_eddsa_pubkey_to_tx_extra(tx.extra, pk));
  ASSERT_TRUE(cryptonote::add_eddsa_signature_to_tx_extra(tx.extra, full_pep_sig));
  ASSERT_TRUE(cryptonote::add_tx_reference_to_tx_extra(tx.extra, tx_ref));
  //get all fields from tx extra
  std::string pep_, lzma_pep_, pseudonym_;
  crypto::hash tx_ref_;
  crypto::public_key pk_;
  crypto::signature full_pep_sig_;

  ASSERT_TRUE(cryptonote::get_lzma_pep_from_tx_extra(tx.extra, lzma_pep_));
  ASSERT_TRUE(lzma_decompress_msg(lzma_pep_, pep_));
  ASSERT_TRUE(cryptonote::get_pseudonym_from_tx_extra(tx.extra, pseudonym_));
  ASSERT_TRUE(cryptonote::get_eddsa_pubkey_from_tx_extra(tx.extra, pk_));
  ASSERT_TRUE(cryptonote::get_eddsa_signature_from_tx_extra(tx.extra, full_pep_sig_));
  ASSERT_TRUE(cryptonote::get_tx_reference_from_tx_extra(tx.extra, tx_ref_));
  //construct full pep for sig. verification
  std::string full_pep_ = pep_ + pseudonym_ + std::string(tx_ref_.data, 32) + std::string(pk_.data, 32);
  ASSERT_TRUE(check_msg_sig(full_pep_, full_pep_sig_, pk_));
}