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
#include "pepenet_social/pep.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "../contrib/epee/include/string_tools.h"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"


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

class pepenet_social_pep_social_args : public testing::Test, public pepenet_social::pep_args {};

/*
  {
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": 1,
      "tx_ref": a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3,
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
*/

std::string msg_ex, pseudonym_ex, sk_seed_ex, pepetag_ex, donation_address_ex;
crypto::hash tx_ref_ex;

TEST_F(pepenet_social_pep_social_args, set_expected_args)
{
  msg_ex = "pepe has a good day";
  pseudonym_ex = "pepe1";
  sk_seed_ex = "123456";
  ASSERT_TRUE(epee::string_tools::hex_to_pod("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", tx_ref_ex));
  pepetag_ex = "good";
  donation_address_ex = "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96";
}

TEST_F(pepenet_social_pep_social_args, parse_json_success1)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1"
    }
	})";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_TRUE(m_pseudonym.value() == pseudonym_ex);
  ASSERT_FALSE(m_sk_seed.has_value());
  ASSERT_FALSE(m_post_pk.has_value());
  ASSERT_FALSE(m_tx_ref.has_value());
  ASSERT_FALSE(m_pepetag.has_value());
  ASSERT_FALSE(m_donation_address.has_value());
}

TEST_F(pepenet_social_pep_social_args, parse_json_success2)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "sk_seed": "123456",
      "post_pk": true
    }
	})";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);
  
  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_FALSE(m_pseudonym.has_value());
  ASSERT_TRUE(m_sk_seed.value() == sk_seed_ex);
  ASSERT_TRUE(m_post_pk.value());
}

TEST_F(pepenet_social_pep_social_args, parse_json_success3)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true
    }
	})";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_TRUE(m_pseudonym.value() == pseudonym_ex);
  ASSERT_TRUE(m_sk_seed.value() == sk_seed_ex);
  ASSERT_TRUE(m_post_pk.value());
  ASSERT_FALSE(m_tx_ref.has_value());
  ASSERT_FALSE(m_pepetag.has_value());
  ASSERT_FALSE(m_donation_address.has_value());
}

TEST_F(pepenet_social_pep_social_args, parse_json_success4)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": false
    }
	})";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_TRUE(m_pseudonym.value() == pseudonym_ex);
  ASSERT_TRUE(m_sk_seed.value() == sk_seed_ex);
  ASSERT_FALSE(m_post_pk.value());
  ASSERT_FALSE(m_tx_ref.has_value());
  ASSERT_FALSE(m_pepetag.has_value());
  ASSERT_FALSE(m_donation_address.has_value());
}

TEST_F(pepenet_social_pep_social_args, parse_json_success5)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    }
	})";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_TRUE(m_pseudonym.value() == pseudonym_ex);
  ASSERT_FALSE(m_sk_seed.has_value());
  ASSERT_FALSE(m_post_pk.has_value());
  ASSERT_TRUE(m_tx_ref.value() == tx_ref_ex);
  ASSERT_FALSE(m_pepetag.has_value());
  ASSERT_FALSE(m_donation_address.has_value());
}

TEST_F(pepenet_social_pep_social_args, parse_json_success6)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good"
    }
	})";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_TRUE(m_pseudonym.value() == pseudonym_ex);
  ASSERT_FALSE(m_sk_seed.has_value());
  ASSERT_FALSE(m_post_pk.has_value());
  ASSERT_TRUE(m_tx_ref.value() == tx_ref_ex);
  ASSERT_TRUE(m_pepetag.value() == pepetag_ex);
  ASSERT_FALSE(m_donation_address.has_value());
}

TEST_F(pepenet_social_pep_social_args, parse_json_success7)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_TRUE(m_pseudonym.value() == pseudonym_ex);
  ASSERT_FALSE(m_sk_seed.has_value());
  ASSERT_FALSE(m_post_pk.has_value());
  ASSERT_TRUE(m_tx_ref.value() == tx_ref_ex);
  ASSERT_TRUE(m_pepetag.value() == pepetag_ex);
  ASSERT_TRUE(m_donation_address.value() == donation_address_ex);
}

TEST_F(pepenet_social_pep_social_args, parse_json_success8)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true,
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })";

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  ASSERT_TRUE(m_msg == msg_ex);
  ASSERT_TRUE(m_pseudonym.value() == pseudonym_ex);
  ASSERT_TRUE(m_sk_seed.value() == sk_seed_ex);
  ASSERT_TRUE(m_post_pk.value());
  ASSERT_TRUE(m_tx_ref.value() == tx_ref_ex);
  ASSERT_TRUE(m_pepetag.value() == pepetag_ex);
  ASSERT_TRUE(m_donation_address.value() == donation_address_ex);
}

TEST_F(pepenet_social_pep_social_args, parse_json_fail_to_load_json)
{
  std::string json_args;
  ASSERT_FALSE(loadJson(json_args).b);
  json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true,
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  )";
  ASSERT_FALSE(loadJson(json_args).b);
  json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456"
      "post_pk": true,
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_01)
{
  std::string json_args = R"({
    "pep_args": {
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_02)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "",
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_03)
{
  std::string json_args = R"({
    "pep_args": {
      "pseudonym": ""
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_04)
{
  std::string json_args = R"({
    "pep_args": {
      "pseudonym": "goodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgood"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_05)
{
  std::string json_args = R"({
    "pep_args": {
      "sk_seed": ""
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_06)
{
  std::string json_args = R"({
    "pep_args": {
      "sk_seed": "123456"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_07)
{
  std::string json_args = R"({
    "pep_args": {
      "sk_seed": "123456",
      "post_pk": 1
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_08)
{
  std::string json_args = R"({
    "pep_args": {
      "sk_seed": "123456",
      "post_pk": 0
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_09)
{
  std::string json_args = R"({
    "pep_args": {
      "post_pk": true
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_10)
{
  std::string json_args = R"({
    "pep_args": {
      "tx_ref": "a665a45920422f"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_11)
{
  std::string json_args = R"({
    "pep_args": {
      "tx_ref": "a665a45920422a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3f"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_12)
{
  std::string json_args = R"({
    "pep_args": {
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27aeK"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_13)
{
  std::string json_args = R"({
    "pep_args": {
      "pepetag": ""
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_14)
{
  std::string json_args = R"({
    "pep_args": {
      "pepetag": "pepepepeeppepepepepppepepepeeppepepepepp"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_15)
{
  std::string json_args = R"({
    "pep_args": {
      "pepetag": "pepepepeeppepepepepppepepepeeppepepepepp"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_16)
{
  std::string json_args = R"({
    "pep_args": {
      "donation_address": ""
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_17)
{
  std::string json_args = R"({
    "pep_args": {
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

TEST_F(pepenet_social_pep_social_args, parse_json_invalid_fields_18)
{
  std::string json_args = R"({
    "pep_args": {
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed9"
    }
  })";
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}