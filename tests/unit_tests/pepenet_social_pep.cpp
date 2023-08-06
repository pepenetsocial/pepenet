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
#include "pepenet_social/pep.h"

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

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

TEST_F(pepenet_social_pep_social_args, parse_json_success_01)
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

TEST_F(pepenet_social_pep_social_args, parse_json_success_02)
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

TEST_F(pepenet_social_pep_social_args, parse_json_success_03)
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

TEST_F(pepenet_social_pep_social_args, parse_json_success_04)
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

TEST_F(pepenet_social_pep_social_args, parse_json_success_05)
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

TEST_F(pepenet_social_pep_social_args, parse_json_success_06)
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

TEST_F(pepenet_social_pep_social_args, parse_json_success_07)
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

TEST_F(pepenet_social_pep_social_args, parse_json_success_08)
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


TEST(pepenet_social_pep_social_feature, load_from_social_args_success_01)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1"
    }
	})";

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  pepenet_social::pep pep_from_bin;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

TEST(pepenet_social_pep_social_feature, load_from_social_args_success_02)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "sk_seed": "123456",
      "post_pk": true
    }
	})";

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  pepenet_social::pep pep_from_bin;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

TEST(pepenet_social_pep_social_feature, load_from_social_args_success_03)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true
    }
	})";

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  pepenet_social::pep pep_from_bin;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

TEST(pepenet_social_pep_social_feature, load_from_social_args_success_04)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": false
    }
	})";

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  crypto::public_key pk;
  crypto::secret_key sk;
  ASSERT_TRUE(pepenet_social::secret_key_from_seed("123456", sk));
  ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));

  pepenet_social::pep pep_from_bin;
  pepenet_social::ibool r;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.validate(pk).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

TEST(pepenet_social_pep_social_feature, load_from_social_args_success_05)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    }
	})";

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  pepenet_social::pep pep_from_bin;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

TEST(pepenet_social_pep_social_feature, load_from_social_args_success_06)
{
  std::string json_args = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good"
    }
	})";

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  pepenet_social::pep pep_from_bin;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

TEST(pepenet_social_pep_social_feature, load_from_social_args_success_07)
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

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  pepenet_social::pep pep_from_bin;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

TEST(pepenet_social_pep_social_feature, load_from_social_args_success_08)
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

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  pepenet_social::pep pep_from_bin;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}