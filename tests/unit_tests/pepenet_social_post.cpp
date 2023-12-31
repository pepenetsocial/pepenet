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

#include "gtest/gtest.h"
#include "pepenet_social/post.h"
#include "pepenet_social_post.h"
#include <google/protobuf/util/json_util.h> 
namespace json_util = google::protobuf::util;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

class pepenet_social_post_social_args : public testing::Test, public pepenet_social::post_args {};
class post_social_args_param : public testing::TestWithParam<std::string> {};
class post_social_args_param_f : public testing::TestWithParam<std::string>, public pepenet_social::post_args {}; //fixture

class pepenet_social_post_social_feature : public testing::TestWithParam<std::string>, public pepenet_social::post {};
class post_social_feature_param_f : public testing::TestWithParam<std::string>, public pepenet_social::post {}; //fixture

/*
  {
    "post_args": {
      "title": "pepe's story",
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true,
      "tx_ref": a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3,
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
*/

static std::string ex_title, ex_msg, ex_pseudonym, ex_sk_seed, ex_pepetag, ex_donation_address;
static crypto::hash ex_tx_ref;
static crypto::public_key ex_pk;

TEST_F(pepenet_social_post_social_args, set_expected_args)
{
  ex_title = "pepe's journey";
  ex_msg = "pepe has a good day";
  ex_pseudonym = "pepe1";
  ex_sk_seed = "123456";
  ASSERT_TRUE(epee::string_tools::hex_to_pod("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", ex_tx_ref));
  ex_pepetag = "good";
  ex_donation_address = "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96";
  crypto::secret_key sk;
  ASSERT_TRUE(pepenet_social::secret_key_from_seed(ex_sk_seed, sk));
  ASSERT_TRUE(crypto::secret_key_to_public_key(sk, ex_pk));
}

#define CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(name) \
{ \
  if (d["post_args"].HasMember(#name))\
  { \
    ASSERT_TRUE(m_##name.has_value()); \
    ASSERT_TRUE(m_##name.value() == ex_##name); \
  } \
  else \
  { \
    ASSERT_FALSE(m_##name.has_value()); \
  } \
} \

#define CHECK_OPT_VARIABLE_HAS_VALUE_IN_JSON_ARGS(name) \
{ \
  if (d["post_args"].HasMember(#name))\
  { \
    ASSERT_TRUE(m_##name.has_value()); \
  } \
  else \
  { \
    ASSERT_FALSE(m_##name.has_value()); \
  } \
} \

class post_social_args_param_f1 : public post_social_args_param_f {};

TEST_P(post_social_args_param_f1, parse_json_success)
{
  std::string json_args = GetParam();

  ASSERT_TRUE(loadJson(json_args).b);
  ASSERT_TRUE(loadArgsFromJson().b);
  ASSERT_TRUE(validate().b);

  rapidjson::Document d;
  ASSERT_FALSE(d.Parse(json_args.data()).HasParseError());

  ASSERT_TRUE(m_title == ex_title);
  ASSERT_TRUE(m_msg == ex_msg);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(pseudonym);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(sk_seed);
  CHECK_OPT_VARIABLE_HAS_VALUE_IN_JSON_ARGS(post_pk);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(tx_ref);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(pepetag);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(donation_address);
}

INSTANTIATE_TEST_CASE_P(
  pepenet_social,
  post_social_args_param_f1,
  ::testing::Values(
    VALID_POST_ARGS
  ));

TEST_F(pepenet_social_post_social_args, parse_json_fail_to_load_json)
{
  std::string json_args;
  ASSERT_FALSE(loadJson(json_args).b);
  json_args = VALID_POST_ARGS_08;
  json_args.pop_back();
  ASSERT_FALSE(loadJson(json_args).b);
  json_args.pop_back();
  ASSERT_FALSE(loadJson(json_args).b);
}

class post_social_args_param_f2 : public post_social_args_param_f {};

TEST_P(post_social_args_param_f2, parse_json_invalid_fields)
{
  std::string json_args = GetParam();
  pepenet_social::ibool r = loadJson(json_args);
  ASSERT_FALSE(loadArgsFromJson().b && r.b);
  ASSERT_FALSE(validate().b);
}

INSTANTIATE_TEST_CASE_P(
  pepenet_social,
  post_social_args_param_f2,
  ::testing::Values(
    INVALID_POST_ARGS
  ));

class post_social_args_param1 : public post_social_args_param {};

TEST_P(post_social_args_param1, load_from_social_args_success)
{
  std::string json_args = GetParam();

  pepenet_social::post_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::post post;
  ASSERT_TRUE(post.loadFromSocialArgs(args).b);
  ASSERT_TRUE(post.validate().b);

  pepenet_social::bytes proto_bytes_in, proto_bytes_out;
  ASSERT_TRUE(post.dumpToBinary(proto_bytes_in).b);

  rapidjson::Document d;
  ASSERT_FALSE(d.Parse(json_args.data()).HasParseError());
  bool generate_pk = d["post_args"].HasMember("post_pk") && d["post_args"]["post_pk"].IsBool() && !d["post_args"]["post_pk"].GetBool();
  crypto::public_key pk;
  crypto::secret_key sk;
  if (generate_pk)
  {
    std::string sk_seed;
    ASSERT_TRUE(d["post_args"].HasMember("sk_seed"));
    ASSERT_TRUE(d["post_args"]["sk_seed"].IsString());
    sk_seed = d["post_args"]["sk_seed"].GetString();
    ASSERT_TRUE(pepenet_social::secret_key_from_seed(sk_seed, sk));
    ASSERT_TRUE(crypto::secret_key_to_public_key(sk, pk));
  }

  pepenet_social::post post_from_bin;
  pepenet_social::ibool r;
  ASSERT_TRUE(post_from_bin.loadFromBinary(proto_bytes_in).b);
  if (generate_pk)
  {
    ASSERT_TRUE(post_from_bin.validate(pk).b);
  }
  ASSERT_TRUE(post_from_bin.dumpToBinary(proto_bytes_out).b);

  ASSERT_EQ(proto_bytes_in, proto_bytes_out);
}

INSTANTIATE_TEST_CASE_P(
  pepenet_social,
  post_social_args_param1,
  ::testing::Values(
    VALID_POST_ARGS
  ));

class post_social_feature_param_f1 : public post_social_feature_param_f {};


TEST_P(post_social_feature_param_f1, load_from_social_args_success_validate_post_internal)
{
  std::string json_args = GetParam();

  pepenet_social::post_args args;
  ASSERT_TRUE(args.loadJson(json_args).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  ASSERT_TRUE(loadFromSocialArgs(args).b);
  ASSERT_TRUE(validate().b);

  rapidjson::Document d;
  ASSERT_FALSE(d.Parse(json_args.data()).HasParseError());

  ASSERT_TRUE(m_title == ex_title);
  ASSERT_TRUE(m_msg == ex_msg);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(pseudonym);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(tx_ref);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(pepetag);
  CHECK_OPT_VARIABLE_EQ_IN_JSON_ARGS(donation_address);
  //check pk and sig
  if (d["post_args"].HasMember("post_pk"))
  {
    ASSERT_TRUE(d["post_args"]["post_pk"].IsBool());
    if (d["post_args"]["post_pk"].GetBool())
    {
      ASSERT_EQ(m_pk.value(), ex_pk);
    }
    ASSERT_TRUE(m_sig.has_value());
  }
}

INSTANTIATE_TEST_CASE_P(
  pepenet_social,
  post_social_feature_param_f1,
  ::testing::Values(
    VALID_POST_ARGS
  ));

TEST_F(pepenet_social_post_social_feature, serialization_stability)
{
  pepenet_social::post_args args;
  ASSERT_FALSE(loadFromSocialArgs(args).b);
  pepenet_social::bytes invalid_bytes_in;
  ASSERT_TRUE(invalid_bytes_in.empty());
  ASSERT_FALSE(loadFromBinary(invalid_bytes_in).b);
  pepenet_social::bytes bytes_out;
  ASSERT_FALSE(dumpToBinary(bytes_out).b);
  ASSERT_TRUE(bytes_out.empty());
}

class post_social_args_param2 : public post_social_args_param {};

TEST_P(post_social_args_param2, load_post_from_binary_success_validation_fail)
{
  std::string json_protobuf = GetParam();

  pepenet_social_protos::post post_dummy_input;
  ASSERT_TRUE(json_util::JsonStringToMessage(json_protobuf, &post_dummy_input).ok());
  pepenet_social::bytes bytes_in;
  ASSERT_TRUE(post_dummy_input.SerializeToString(&bytes_in));

  pepenet_social::post post;
  ASSERT_FALSE(post.loadFromBinary(bytes_in).b);
  ASSERT_FALSE(post.validate().b);
}

INSTANTIATE_TEST_CASE_P(
  pepenet_social,
  post_social_args_param2,
  ::testing::Values(
    INVALID_POST_PROTOBUFS_JSON
  ));