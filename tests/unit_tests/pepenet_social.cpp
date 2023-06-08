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

TEST(pepenet_social, lzma_compress_decompress)
{
  std::string msg = "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS ANDHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDEHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDE";
  std::string out;
  ASSERT_TRUE(pepenet_social::lzma_compress_msg(msg, out));
  ASSERT_TRUE(out.size() < msg.size());

  std::string msg_decopressed;
  ASSERT_TRUE(pepenet_social::lzma_decompress_msg(out, msg_decopressed));
  ASSERT_TRUE(msg_decopressed == msg);
}

TEST(pepenet_social, sing_verify_msg_1)
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
  ASSERT_TRUE(pepenet_social::lzma_compress_msg(pep, lzma_pep));
  //get keys
  crypto::public_key pk;
  crypto::secret_key sk;
  ASSERT_TRUE(pepenet_social::secret_key_from_seed(sk_seed, sk));
  ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));
  crypto::signature full_pep_sig;
  //contruct full content for signing
  std::string full_pep = pep + pseudonym + std::string(tx_ref.data, 32) + std::string(pk.data, 32);
  pepenet_social::sign_msg(full_pep, full_pep_sig, pk, sk);
  //add all fields to extra
  ASSERT_TRUE(cryptonote::add_lzma_pep_to_tx_extra(tx.extra, lzma_pep));
  ASSERT_TRUE(cryptonote::add_pseudonym_to_tx_extra(tx.extra, pseudonym));
  ASSERT_TRUE(cryptonote::add_eddsa_pubkey_to_tx_extra(tx.extra, pk));
  ASSERT_TRUE(cryptonote::add_eddsa_signature_to_tx_extra(tx.extra, full_pep_sig));
  ASSERT_TRUE(cryptonote::add_tx_reference_to_tx_extra(tx.extra, tx_ref));
  //get all fields from tx extra
  std::string pep_, lzma_pep_;
  boost::optional<std::string> pseudonym_;
  boost::optional<crypto::hash> tx_ref_;
  boost::optional<crypto::public_key> pk_;
  boost::optional<crypto::signature> full_pep_sig_;

  ASSERT_TRUE(cryptonote::get_lzma_pep_from_tx_extra(tx.extra, lzma_pep_));
  ASSERT_TRUE(pepenet_social::lzma_decompress_msg(lzma_pep_, pep_));
  ASSERT_TRUE(cryptonote::get_pseudonym_from_tx_extra(tx.extra, pseudonym_));
  ASSERT_TRUE(cryptonote::get_eddsa_pubkey_from_tx_extra(tx.extra, pk_));
  ASSERT_TRUE(cryptonote::get_eddsa_signature_from_tx_extra(tx.extra, full_pep_sig_));
  ASSERT_TRUE(cryptonote::get_tx_reference_from_tx_extra(tx.extra, tx_ref_));
  //construct full pep for sig. verification
  std::string full_pep_ = pep_ + pseudonym_.value() + std::string(tx_ref_.value().data, 32) + std::string(pk_.value().data, 32);
  ASSERT_TRUE(pepenet_social::check_msg_sig(full_pep_, full_pep_sig_.value(), pk_.value()));
}

TEST(pepenet_social_valid_pep, pep_to_extra_verification_validity_1)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) && pep.has_value());
}

TEST(pepenet_social_valid_pep, pep_to_extra_verification_validity_2)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) && pep.has_value());
}

TEST(pepenet_social_valid_pep, pep_to_extra_verification_validity_3)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) && pep.has_value());
}

TEST(pepenet_social_valid_pep, pep_to_extra_verification_validity_4)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) && pep.has_value());
}

TEST(pepenet_social_valid_pep, pep_to_extra_verification_validity_5)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) && pep.has_value());
}

TEST(pepenet_social_valid_pep, pep_to_extra_verification_validity_6)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = false;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::pep> pep;
  //get sk and pk
  crypto::secret_key sk;
  crypto::public_key pk;
  pepenet_social::secret_key_from_seed(sk_seed, sk);
  crypto::secret_key_to_public_key(sk, pk);
  ASSERT_TRUE(pepenet_social::get_and_verify_pep_from_tx_extra(pk, pep, tx.extra, social_err) && pep.has_value());
  ASSERT_FALSE(pep.value().pk.has_value());
}

TEST(pepenet_social_valid_tx, no_pep_extra_verification_validity)
{
  cryptonote::transaction tx;

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(!pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) && pep.has_value());
}

TEST(pepenet_social_valid_post, post_to_extra_verification_validity_1)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) && post.has_value());
}

TEST(pepenet_social_valid_post, post_to_extra_verification_validity_2)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) && post.has_value());
}

TEST(pepenet_social_valid_post, post_to_extra_verification_validity_3)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) && post.has_value());
}

TEST(pepenet_social_valid_post, post_to_extra_verification_validity_4)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) && post.has_value());
}

TEST(pepenet_social_valid_post, post_to_extra_verification_validity_5)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) && post.has_value());
}

TEST(pepenet_social_valid_post, post_to_extra_verification_validity_6)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = false;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  //get sk and pk
  crypto::secret_key sk;
  crypto::public_key pk;
  pepenet_social::secret_key_from_seed(sk_seed, sk);
  crypto::secret_key_to_public_key(sk, pk);
  ASSERT_TRUE(pepenet_social::get_and_verify_post_from_tx_extra(pk, post, tx.extra, social_err) && post.has_value());
  ASSERT_FALSE(post.value().pk.has_value());
}

TEST(pepenet_social_valid_tx, no_post_extra_verification_validity)
{
  cryptonote::transaction tx;

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(!pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) && post.has_value());
}

TEST(pepenet_social_invalid_pep, pep_from_extra_missing_msg)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_pep));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err));
  ASSERT_FALSE(pep.has_value());
}

TEST(pepenet_social_invalid_pep, pep_from_extra_lzma_failed)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_pep));
  cryptonote::add_lzma_pep_to_tx_extra(tx.extra, "");

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err));
  ASSERT_FALSE(pep.has_value());
}

TEST(pepenet_social_invalid_pep, pep_from_extra_invalid_sig)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra - causes invalid sig. verification
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_tx_reference));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) || pep.has_value());
}

TEST(pepenet_social_invalid_pep, pep_from_extra_pk_present_sig_not)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra - pk present, sig not present - invalid tx !
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_eddsa_signature));

  boost::optional<pepenet_social::pep> pep;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, social_err) || pep.has_value());
}

TEST(pepenet_social_invalid_post, post_from_extra_missing_msg)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.title = "pepe has a good day!";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_post));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err));
  ASSERT_FALSE(post.has_value());
}

TEST(pepenet_social_invalid_post, post_from_extra_missing_title)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_post));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err));
  ASSERT_FALSE(post.has_value());
}

TEST(pepenet_social_invalid_post, post_from_extra_missing_msg_and_title)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_post));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err));
  ASSERT_FALSE(post.has_value());
}

TEST(pepenet_social_invalid_post, post_from_extra_lzma_failed)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "pepe has a good day!";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_post));
  cryptonote::add_lzma_post_to_tx_extra(tx.extra, "");

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err));
  ASSERT_FALSE(post.has_value());
}

TEST(pepenet_social_invalid_post, post_from_extra_invalid_sig)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "pepe has a good day!";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra - causes invalid sig. verification
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_tx_reference));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) || post.has_value());
}

TEST(pepenet_social_invalid_post, post_from_extra_pk_present_sig_not)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "pepe has a good day!";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  //remove field from extra - pk present, sig not present - invalid tx !
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_eddsa_signature));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, social_err) || post.has_value());
}

TEST(pepenet_social_tx_validity, tx_with_no_social_features)
{
  cryptonote::transaction tx;

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_tx_validity, tx_w_valid_pep)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_tx_validity, tx_w_invalid_pep)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_pep));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_tx_validity, tx_w_valid_post)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_tx_validity, tx_w_invalid_post)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_lzma_post));
  cryptonote::remove_field_from_tx_extra(tx.extra, typeid(cryptonote::tx_extra_post_title));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_tx_validity, tx_w_valid_post_and_pep_tag)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::post_args p;
  p.msg = "2992993390";
  p.title = "good day for pepe";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(p, tx.extra, social_err));
  std::string lzma_pep;
  ASSERT_TRUE(pepenet_social::lzma_compress_msg(p.msg, lzma_pep));
  ASSERT_TRUE(cryptonote::add_lzma_pep_to_tx_extra(tx.extra, lzma_pep));

  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_tx_validity, tx_w_valid_pep_and_post_tag)
{
  std::string tx_h_in = "slslls";
  std::string sk_seed = "1498b5467a63dffa2dc9d9e069caf075d16fc33fdd4c3b01bfadae6433767d93";
  pepenet_social::pep_args p;
  p.msg = "2992993390";
  p.pseudonym = "jsaiiwjskis";
  p.sk_seed = sk_seed;
  p.post_pk = true;
  p.tx_ref = crypto::cn_fast_hash(tx_h_in.data(), tx_h_in.size());
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(p, tx.extra, social_err));
  cryptonote::transaction tx_title = tx, tx_post_title = tx;
  std::string lzma_post;
  ASSERT_TRUE(pepenet_social::lzma_compress_msg(p.msg, lzma_post));
  ASSERT_TRUE(cryptonote::add_lzma_post_to_tx_extra(tx.extra, lzma_post));

  ASSERT_TRUE(cryptonote::add_lzma_post_to_tx_extra(tx_title.extra, "good pepe good"));

  ASSERT_TRUE(cryptonote::add_lzma_post_to_tx_extra(tx_post_title.extra, lzma_post));
  ASSERT_TRUE(cryptonote::add_lzma_post_to_tx_extra(tx_post_title.extra, "good pepe good"));
  
  boost::optional<pepenet_social::post> post;
  boost::optional<crypto::public_key> null_pk;
  ASSERT_FALSE(pepenet_social::check_tx_social_validity(tx));
  ASSERT_FALSE(pepenet_social::check_tx_social_validity(tx_title));
  ASSERT_FALSE(pepenet_social::check_tx_social_validity(tx_post_title));
}

TEST(pepenet_social_transfer, parse_transfer_main_args)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "pseudonym=pepe1", "sk_seed=h12992020", "post_pk=1", "tx_reference=b3f6e61f58137b35a1376a0861d906bc9560cc46ba50173c8c6600488fad3956" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);
  
  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_TRUE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    std::string pseudonym;
    if (!parse_str("pseudonym=", pseudonym, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    std::string sk_seed;
    if (!parse_str("sk_seed=", sk_seed, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    bool sk_seed_arg_missing = arg_missing;
    std::string post_pk_;
    if (!parse_str("post_pk=", post_pk_, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!sk_seed_arg_missing && arg_missing)
    {
      ASSERT_TRUE(false);
    }
    GTEST_COUT << "post_pk: " << post_pk_ << std::endl;
    
    bool post_pk;
    if (!sk_seed_arg_missing)
    {
      if (post_pk_ == "1")
      {
        post_pk = true;
      }
      else if (post_pk_ == "0")
      {
        post_pk = false;
      }
      else
      {
        ASSERT_TRUE(false);
      }
    }

    crypto::hash tx_reference;
    std::string tx_ref_hex;
    if (!parse_str("tx_reference=", tx_ref_hex, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_reference))
    {
      ASSERT_TRUE(false);
    }
    //TODO: check if tx exists in db
    //construct args
    if (pep_arg)
    {
      pep_args.pseudonym = pseudonym;
      pep_args.sk_seed = sk_seed;
      pep_args.post_pk = post_pk;
      pep_args.tx_ref = tx_reference;
    }
    if (post_arg && post_title_arg)
    {
      post_args.pseudonym = pseudonym;
      post_args.sk_seed = sk_seed;
      post_args.post_pk = post_pk;
      post_args.tx_ref = tx_reference;
    }

  }
  cryptonote::transaction tx;
  //add pep or post to tx
  if (pep_arg)
  {
    boost::optional<std::string> err;
    if (!pepenet_social::add_pep_to_tx_extra(pep_args, tx.extra, err))
    {
      ASSERT_TRUE(false);
    }
  }
  else if (post_arg && post_title_arg)
  {
    boost::optional<std::string> err;
    if (!pepenet_social::add_post_to_tx_extra(post_args, tx.extra, err))
    {
      ASSERT_TRUE(false);
    }
  }
  //verify tx
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_transfer, parse_transfer_main_args_invalid_tx_ref_1)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "pseudonym=pepe1", "sk_seed=h12992020", "post_pk=1", "tx_reference=Kf58137b35a1376a0861d906bc9560cc46ba50173c8c6600488fad3956" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_TRUE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    std::string pseudonym;
    if (!parse_str("pseudonym=", pseudonym, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    std::string sk_seed;
    if (!parse_str("sk_seed=", sk_seed, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    bool sk_seed_arg_missing = arg_missing;
    std::string post_pk_;
    if (!parse_str("post_pk=", post_pk_, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!sk_seed_arg_missing && arg_missing)
    {
      ASSERT_TRUE(false);
    }
    GTEST_COUT << "post_pk: " << post_pk_ << std::endl;

    bool post_pk;
    if (!sk_seed_arg_missing)
    {
      if (post_pk_ == "1")
      {
        post_pk = true;
      }
      else if (post_pk_ == "0")
      {
        post_pk = false;
      }
      else
      {
        ASSERT_TRUE(false);
      }
    }

    crypto::hash tx_reference;
    std::string tx_ref_hex;
    if (!parse_str("tx_reference=", tx_ref_hex, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_reference))
    {
      ASSERT_FALSE(false);
    }
  }
}

TEST(pepenet_social_transfer, parse_transfer_main_args_invalid_tx_ref_2)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "pseudonym=pepe1", "sk_seed=h12992020", "post_pk=1", "tx_reference=b35a1376a0861d906bc9560cc46ba50173c8c6600488fad3956" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_TRUE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    std::string pseudonym;
    if (!parse_str("pseudonym=", pseudonym, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    std::string sk_seed;
    if (!parse_str("sk_seed=", sk_seed, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    bool sk_seed_arg_missing = arg_missing;
    std::string post_pk_;
    if (!parse_str("post_pk=", post_pk_, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!sk_seed_arg_missing && arg_missing)
    {
      ASSERT_TRUE(false);
    }
    GTEST_COUT << "post_pk: " << post_pk_ << std::endl;

    bool post_pk;
    if (!sk_seed_arg_missing)
    {
      if (post_pk_ == "1")
      {
        post_pk = true;
      }
      else if (post_pk_ == "0")
      {
        post_pk = false;
      }
      else
      {
        ASSERT_TRUE(false);
      }
    }

    crypto::hash tx_reference;
    std::string tx_ref_hex;
    if (!parse_str("tx_reference=", tx_ref_hex, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_reference))
    {
      ASSERT_FALSE(false);
    }
  }
}

TEST(pepenet_social_transfer, parse_transfer_main_args_missing_pk_arg)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "pseudonym=pepe1", "sk_seed=h12992020", "tx_reference=b3f6e61f58137b35a1376a0861d906bc9560cc46ba50173c8c6600488fad3956" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_TRUE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    std::string pseudonym;
    if (!parse_str("pseudonym=", pseudonym, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    std::string sk_seed;
    if (!parse_str("sk_seed=", sk_seed, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    bool sk_seed_arg_missing = arg_missing;
    ASSERT_FALSE(sk_seed_arg_missing);
    
    std::string post_pk_;
    if (!parse_str("post_pk=", post_pk_, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!sk_seed_arg_missing && arg_missing)
    {
      ASSERT_FALSE(false);
      goto end_pk_missing;
    }
  }
  ASSERT_TRUE(false);
  end_pk_missing:
  ASSERT_TRUE(true);
}

TEST(pepenet_social_transfer, parse_transfer_main_args_post_and_pep_args_1)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "post=pepe's post", "post_title=pepe title" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_FALSE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
}

TEST(pepenet_social_transfer, parse_transfer_main_args_post_and_pep_args_2)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "post=pepe's post" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_FALSE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_FALSE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
}

TEST(pepenet_social_transfer, parse_transfer_main_args_post_and_pep_args_3)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "post_title=pepe title" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_FALSE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_FALSE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
}

TEST(pepenet_social_transfer, parse_transfer_main_args_post_and_pep_args_4)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = {"post_title=pepe title"};
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_FALSE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_TRUE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
}

TEST(pepenet_social_transfer, parse_transfer_main_args_post_and_pep_args_5)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "post=pepe title" };
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());
      
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_FALSE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_TRUE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
}

TEST(pepenet_social_pep_optional_fields, pep_to_extra_optional_fields_1)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::vector<std::string> args_ = { "pep=hello pepe", "pseudonym=pepe1"};
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;

    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());

      return true;
    }
    arg_missing = true;
    return false;
  };

  auto parse_str_opt = [](const std::string& target_arg, boost::optional<std::string>& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;
    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.value().length())
        return false;
      local_args.erase(local_args.begin());
      return true;
    }
    arg_missing = true;
    return false;
  };

  pepenet_social::pep_args pep_args;
  pepenet_social::post_args post_args;
  bool arg_missing;
  bool pep_arg = parse_str("pep=", pep_args.msg, local_args, arg_missing);
  bool post_arg = parse_str("post=", post_args.msg, local_args, arg_missing);
  bool post_title_arg = parse_str("post_title=", post_args.title, local_args, arg_missing);

  if ((post_arg && !post_title_arg) || (!post_arg && post_title_arg))
  {
    ASSERT_TRUE(false);
  }
  if ((pep_arg && (post_arg || post_title_arg)))
  {
    ASSERT_TRUE(false);
  }
  else if ((pep_arg) || (post_arg && post_title_arg))
  {
    boost::optional<std::string> pseudonym;
    if (!parse_str_opt("pseudonym=", pseudonym, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    boost::optional<std::string> sk_seed;
    if (!parse_str_opt("sk_seed=", sk_seed, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    bool sk_seed_arg_missing = arg_missing;
    std::string post_pk_;
    if (!parse_str("post_pk=", post_pk_, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!sk_seed_arg_missing && arg_missing)
    {
      ASSERT_TRUE(false);
    }
    GTEST_COUT << "post_pk: " << post_pk_ << std::endl;

    bool post_pk;
    if (!sk_seed_arg_missing)
    {
      if (post_pk_ == "1")
      {
        post_pk = true;
      }
      else if (post_pk_ == "0")
      {
        post_pk = false;
      }
      else
      {
        ASSERT_TRUE(false);
      }
    }

    boost::optional<crypto::hash> tx_reference;
    std::string tx_ref_hex;
    if (!parse_str("tx_reference=", tx_ref_hex, local_args, arg_missing) && !arg_missing)
    {
      ASSERT_TRUE(false);
    }
    if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_reference))
    {
      ASSERT_FALSE(false);
    }
    //TODO: check if tx exists in db
    //construct args
    if (pep_arg)
    {
      pep_args.pseudonym = pseudonym;
      pep_args.sk_seed = sk_seed;
      pep_args.post_pk = post_pk;
      pep_args.tx_ref = tx_reference;
    }
    if (post_arg && post_title_arg)
    {
      post_args.pseudonym = pseudonym;
      post_args.sk_seed = sk_seed;
      post_args.post_pk = post_pk;
      post_args.tx_ref = tx_reference;
    }

  }
  cryptonote::transaction tx;
  //add pep or post to tx
  if (pep_arg)
  {
    boost::optional<std::string> err;
    if (!pepenet_social::add_pep_to_tx_extra(pep_args, tx.extra, err))
    {
      ASSERT_TRUE(false);
    }
  }
  else if (post_arg && post_title_arg)
  {
    boost::optional<std::string> err;
    if (!pepenet_social::add_post_to_tx_extra(post_args, tx.extra, err))
    {
      ASSERT_TRUE(false);
    }
  }
  //verify tx
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
  boost::optional<crypto::public_key> null_pk;
  boost::optional<pepenet_social::pep> pep;
  boost::optional<std::string> err;
  ASSERT_TRUE(get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, err));
  ASSERT_TRUE(!pep.value().sig.has_value());
  ASSERT_TRUE(!pep.value().tx_ref.has_value());

  //hash
  crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);
  crypto::hash empty_hash;
}

TEST(pepenet_social_msg_args, pep_msg_arg)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::string pep_arg_string = "pep=<msg>I had a great day today. Feels good man :D. I should try this more often.It might even benefit me some day !</msg> pseudonym=pepe1";
  std::string target_pep_content = "I had a great day today. Feels good man :D. I should try this more often.It might even benefit me some day !";
  
  std::vector<std::string> args_ = {pep_arg_string };
  args_ = boost::split(args_, pep_arg_string, boost::is_any_of(" "), boost::token_compress_on);
  std::vector<std::string> local_args = args_;
  //parse social args
  auto parse_str = [](const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
  {
    arg_missing = false;

    if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    {
      val = local_args[0].substr(target_arg.length());
      if (!val.length())
        return false;
      local_args.erase(local_args.begin());

      return true;
    }
    arg_missing = true;
    return false;
  };

  std::string pep_begin;
  bool arg_missing;
  ASSERT_TRUE(parse_str("pep=<msg>", pep_begin, local_args, arg_missing));
  pep_begin += " ";
  std::vector<std::string>::iterator it = std::find_if(local_args.begin(), local_args.end(), [](const std::string& s)
    {return boost::algorithm::ends_with(s, "</msg>");}
  );
  ASSERT_TRUE(it != local_args.end());
  //remove end 
  boost::algorithm::replace_all(*it, "</msg>", "");
  // add spaces
  for (auto it_ = local_args.begin(); it_ != it; ++it_)
    *it_ += " ";
  
  std::string pep_content = std::accumulate(local_args.begin(), it, pep_begin);
  pep_content += *it;
  
  ASSERT_TRUE(pep_content == target_pep_content);
  local_args.erase(local_args.begin(), it +1);
  
  ASSERT_TRUE(local_args.size() == 1 && local_args[0] == "pseudonym=pepe1");
}

bool parse_str(const std::string& target_arg, std::string& val, std::vector<std::string>& local_args, bool& arg_missing)
{
  arg_missing = false;
  if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
  {
    val = local_args[0].substr(target_arg.length());
    if (!val.length())
      return false;
    local_args.erase(local_args.begin());
    return true;
  }
  arg_missing = true;
  return false;
}

bool check_arg(const std::string& target_arg, const std::vector<std::string>& local_args)
{
  if (local_args.size() > 0 && local_args[0].substr(0, target_arg.length()) == target_arg)
    return true;
  return false;
};

bool parse_msg_tag(const std::string& arg_with_msg_tag, std::string& result, std::vector<std::string>& local_args) {
  std::string msg_begin;
  bool arg_missing = false;
  std::string target = arg_with_msg_tag + "<msg>";
  if (!parse_str(target, msg_begin, local_args, arg_missing))
  {
    return false;
  }
  msg_begin += " ";
  std::vector<std::string>::iterator it = std::find_if(local_args.begin(), local_args.end(), [](const std::string& s)
    {return boost::algorithm::ends_with(s, "</msg>");}
  );
  if (it == local_args.end())
  {
    return false;
  }
  //remove end 
  boost::algorithm::replace_all(*it, "</msg>", "");
  // add spaces
  for (auto it_ = local_args.begin(); it_ != it; ++it_)
    *it_ += " ";

  result = std::accumulate(local_args.begin(), it, msg_begin);
  result += *it;
  local_args.erase(local_args.begin(), it + 1);
  return true;
}

TEST(pepenet_social_msg_args, pep_msg_arg_parse_msg_tag_test)
{
  //  "transfer [pep=<msg>] [post=<msg>] [post_title=<msg>] [pseudonym=<str>] [sk_seed=<str>] [post_pk=<1/0>] [tx_reference=<tx hash>] [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
  std::string pep_arg_string = "pep=<msg>I had a great day today. Feels good man :D. I should try this more often.It might even benefit me some day !</msg> pseudonym=pepe1";
  std::string target_pep_content = "I had a great day today. Feels good man :D. I should try this more often.It might even benefit me some day !";

  std::vector<std::string> args_ = { pep_arg_string };
  args_ = boost::split(args_, pep_arg_string, boost::is_any_of(" "), boost::token_compress_on);
  std::vector<std::string> local_args = args_;
  //parse social args
  bool arg_missing;
  bool pep_tag_missing = false;
  std::string msg_str;

  bool pep_arg = check_arg("pep=", local_args);
  ASSERT_TRUE(parse_msg_tag("pep=", msg_str, local_args));
}

TEST(pepenet_social_social_msg_args, pk_filter_1)
{
  crypto::public_key pk_filter;
  boost::optional<crypto::public_key> pk_filter_opt;
  std::string pk_filter_hex;
  bool arg_missing;
  std::vector<std::string> local_args = { "pubkey_filter=dceb95b3eb74c38c371d5772311cc32acba6ebd0e7d97e4ffb338c947e6bac14" };
  if (!parse_str("pubkey_filter=", pk_filter_hex, local_args, arg_missing) && !arg_missing)
  {
    ASSERT_TRUE(false);
  }
  if (!epee::string_tools::hex_to_pod(pk_filter_hex, pk_filter) && !arg_missing)
  {
    ASSERT_TRUE(false);
  }
  else
  {
    pk_filter_opt = pk_filter;
  }
}