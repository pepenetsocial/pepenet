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
class pep_social_args_param : public testing::TestWithParam<std::string> {};
class pep_social_args_param_f : public testing::TestWithParam<std::string>, public pepenet_social::pep_args {}; //fixture

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

TEST_P(pep_social_args_param_f, parse_json_invalid_fields)
{
  std::string json_args = GetParam();
  ASSERT_FALSE(loadJson(json_args).b);
  ASSERT_FALSE(loadArgsFromJson().b);
  ASSERT_FALSE(validate().b);
}

INSTANTIATE_TEST_SUITE_P(
  pepenet_social,
  pep_social_args_param_f,
  ::testing::Values(
    std::string(R"({
    "pep_args": {
    }
  })"),
    std::string(R"({
    "pep_args": {
      "msg": "",
    }
  })"),
    std::string(R"({
    "pep_args": {
      "pseudonym": ""
    }
  })"),
    std::string(R"({
    "pep_args": {
      "pseudonym": "goodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgood"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "sk_seed": ""
    }
  })"),
    std::string(R"({
    "pep_args": {
      "sk_seed": "123456"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "sk_seed": "123456",
      "post_pk": 1
    }
  })"),
    std::string(R"({
    "pep_args": {
      "sk_seed": "123456",
      "post_pk": 0
    }
  })"),
    std::string(R"({
    "pep_args": {
      "post_pk": true
    }
  })"),
    std::string(R"({
    "pep_args": {
      "tx_ref": "a665a45920422f"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "tx_ref": "a665a45920422a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3f"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27aeK"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "pepetag": ""
    }
  })"),
    std::string(R"({
    "pep_args": {
      "pepetag": "pepepepeeppepepepepppepepepeeppepepepepp"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "pepetag": "pepepepeeppepepepepppepepepeeppepepepepp"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "donation_address": ""
    }
  })"),
    std::string(R"({
    "pep_args": {
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed9"
    }
  })")
  ));

TEST_P(pep_social_args_param, load_from_social_args_success)
{
  std::string json_args = GetParam();

  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(proto_bytes_in).b);

  rapidjson::Document d;
  ASSERT_FALSE(d.Parse(json_args.data()).HasParseError());
  bool generate_pk = d["pep_args"].HasMember("post_pk") && d["pep_args"]["post_pk"].IsBool() && !d["pep_args"]["post_pk"].GetBool();
  crypto::public_key pk;
  crypto::secret_key sk;
  if (generate_pk)
  {
    std::string sk_seed;
    ASSERT_TRUE(d["pep_args"].HasMember("sk_seed"));
    ASSERT_TRUE(d["pep_args"]["sk_seed"].IsString());
    sk_seed = d["pep_args"]["sk_seed"].GetString();
    ASSERT_TRUE(pepenet_social::secret_key_from_seed(sk_seed, sk));
    ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));
  }

  pepenet_social::pep pep_from_bin;
  pepenet_social::ibool r;
  ASSERT_TRUE(pep_from_bin.loadFromBinary(proto_bytes_in).b);
  if (generate_pk)
  {
    ASSERT_TRUE(pep_from_bin.validate(pk).b);
  }
  ASSERT_TRUE(pep_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

INSTANTIATE_TEST_SUITE_P(
  pepenet_social,
  pep_social_args_param,
  ::testing::Values(
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1"
    }
	})"),
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "sk_seed": "123456",
      "post_pk": true
    }
	})"),
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true
    }
	})"),
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": false
    }
	})"),
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    }
	})"),
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good"
    }
	})"),
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })"),
    std::string(R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true,
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })")
  ));