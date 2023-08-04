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