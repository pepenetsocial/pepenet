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

#include "pepenet_social/social_helpers.h"
#include "../contrib/epee/include/string_tools.h"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "pepenet_social_pep.h"
#include "pepenet_social_post.h"
#include "pepenet_social/pepenet_social.h"

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

TEST(pepenet_social_functions, lzma_decompresssion_function_stability)
{
  std::string invalid_compressed_data = "1828771932sslla";
  std::string decompressed_out;
  ASSERT_FALSE(pepenet_social::lzma_decompress_msg(invalid_compressed_data, decompressed_out));
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

TEST(pepenet_social_transactions, valid_transaction_pep_to_from_tx_extra)
{
  pepenet_social::pep_args args;
  ASSERT_TRUE(args.loadJson(VALID_PEP_ARGS_08).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::pep pep;
  ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
  ASSERT_TRUE(pep.validate().b);
  pepenet_social::bytes pep_bytes_in, pep_bytes_out;
  ASSERT_TRUE(pep.dumpToBinary(pep_bytes_in).b);
  cryptonote::transaction tx;

  boost::optional<pepenet_social::pep> tx_extra_pep;
  ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(pep, tx.extra).b);
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
  ASSERT_TRUE(pepenet_social::get_and_verify_pep_from_tx_extra(tx_extra_pep, tx.extra).b);
  ASSERT_TRUE(tx_extra_pep.has_value());
  ASSERT_TRUE(tx_extra_pep.value().dumpToBinary(pep_bytes_out).b);
  ASSERT_EQ(pep_bytes_in, pep_bytes_out);
}

TEST(pepenet_social_transactions, valid_transaction_post_to_from_tx_extra)
{
  pepenet_social::post_args args;
  ASSERT_TRUE(args.loadJson(VALID_POST_ARGS_08).b);
  ASSERT_TRUE(args.loadArgsFromJson().b);
  ASSERT_TRUE(args.validate().b);

  pepenet_social::post post;
  ASSERT_TRUE(post.loadFromSocialArgs(args).b);
  ASSERT_TRUE(post.validate().b);
  pepenet_social::bytes post_bytes_in, post_bytes_out;
  ASSERT_TRUE(post.dumpToBinary(post_bytes_in).b);
  cryptonote::transaction tx;

  boost::optional<pepenet_social::post> tx_extra_post;
  ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(post, tx.extra).b);
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
  pepenet_social::ibool r = pepenet_social::get_and_verify_post_from_tx_extra(tx_extra_post, tx.extra);
  GTEST_COUT << "get_and_verify_post_from_tx_extra: " << r.info.value_or("") << std::endl;
  ASSERT_TRUE(r.b);
  ASSERT_TRUE(tx_extra_post.has_value());
  ASSERT_TRUE(tx_extra_post.value().dumpToBinary(post_bytes_out).b);
  ASSERT_EQ(post_bytes_in, post_bytes_out);
}

TEST(pepenet_social_transactions, valid_transaction_no_social_features)
{
  cryptonote::transaction tx;
  ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_transactions, invalid_transaction_pep_and_post)
{
  cryptonote::transaction tx;
  pepenet_social::pep pep;
  pepenet_social::post post;
  
  {
    pepenet_social::pep_args args;
    ASSERT_TRUE(args.loadJson(VALID_PEP_ARGS_08).b);
    ASSERT_TRUE(args.loadArgsFromJson().b);
    ASSERT_TRUE(args.validate().b);
    ASSERT_TRUE(pep.loadFromSocialArgs(args).b);
    ASSERT_TRUE(pep.validate().b);
    ASSERT_TRUE(pepenet_social::add_pep_to_tx_extra(pep, tx.extra).b);
  }

  {
    pepenet_social::post_args args;
    ASSERT_TRUE(args.loadJson(VALID_POST_ARGS_08).b);
    ASSERT_TRUE(args.loadArgsFromJson().b);
    ASSERT_TRUE(args.validate().b);
    ASSERT_TRUE(post.loadFromSocialArgs(args).b);
    ASSERT_TRUE(post.validate().b);
    ASSERT_TRUE(pepenet_social::add_post_to_tx_extra(post, tx.extra).b);
  }
  
  ASSERT_FALSE(pepenet_social::check_tx_social_validity(tx));
}

TEST(pepenet_social_transactions, valid_transaction_post_to_from_tx_extra_compression_stability)
{
  auto add_post_to_tx_extra = [](pepenet_social::post& post, std::vector<uint8_t>& tx_extra)
    {
      post.validate();
      pepenet_social::bytes proto_bytes, compressed_proto_bytes;
      ASSERT_TRUE(post.dumpToBinary(proto_bytes).b);
      //compress
      ASSERT_TRUE(pepenet_social::lzma_compress_msg(proto_bytes, compressed_proto_bytes));
      {
        pepenet_social::bytes decompressed_bytes_test;
        ASSERT_TRUE(pepenet_social::lzma_decompress_msg(compressed_proto_bytes, decompressed_bytes_test));
        ASSERT_EQ(proto_bytes, decompressed_bytes_test);
      }
      ASSERT_TRUE(cryptonote::add_social_feature_to_tx_extra(tx_extra, compressed_proto_bytes, POST_SOCIAL_FEATURE_TAG));

      {
        size_t feature_id;
        pepenet_social::bytes proto_bytes_d, compressed_proto_bytes;
        ASSERT_TRUE(cryptonote::get_social_feature_from_tx_extra(tx_extra, compressed_proto_bytes, feature_id));
        ASSERT_TRUE(feature_id == POST_SOCIAL_FEATURE_TAG);
        //decompress
        ASSERT_TRUE(pepenet_social::lzma_decompress_msg(compressed_proto_bytes, proto_bytes_d));
        ASSERT_EQ(proto_bytes, proto_bytes_d);
        pepenet_social::post tx_extra_post;
        ASSERT_TRUE(tx_extra_post.loadFromBinary(proto_bytes_d).b);
        post = tx_extra_post;
      }
    };


  auto get_and_verify_post_from_tx_extra = [](boost::optional<pepenet_social::post>& post, const std::vector<uint8_t>& tx_extra)
    {
      size_t feature_id;
      pepenet_social::bytes proto_bytes, compressed_proto_bytes;
      CHECK_AND_ASSERT_RETURN_IBOOL(cryptonote::get_social_feature_from_tx_extra(tx_extra, compressed_proto_bytes, feature_id), "failed to get post bytes from tx_extra");
      CHECK_AND_ASSERT_RETURN_IBOOL(feature_id == POST_SOCIAL_FEATURE_TAG, "post not found in tx extra");
      //decompress
      CHECK_AND_ASSERT_RETURN_IBOOL(pepenet_social::lzma_decompress_msg(compressed_proto_bytes, proto_bytes), "failed to decompress post proto bytes");
      pepenet_social::post tx_extra_post;
      CHECK_AND_ASSERT_RETURN_IBOOL(tx_extra_post.loadFromBinary(proto_bytes).b, "failed to load post from binary");
      post = tx_extra_post;
      return pepenet_social::ibool{ true, INFO_NULLOPT };
    };

    for (size_t i = 0; i < 20; ++i)
    {
      pepenet_social::post_args args;
      ASSERT_TRUE(args.loadJson(VALID_POST_ARGS_08).b);
      ASSERT_TRUE(args.loadArgsFromJson().b);
      ASSERT_TRUE(args.validate().b);

      pepenet_social::post post;
      ASSERT_TRUE(post.loadFromSocialArgs(args).b);
      ASSERT_TRUE(post.validate().b);
      pepenet_social::bytes post_bytes_in, post_bytes_out;
      ASSERT_TRUE(post.dumpToBinary(post_bytes_in).b);
      cryptonote::transaction tx;

      boost::optional<pepenet_social::post> tx_extra_post;
      add_post_to_tx_extra(post, tx.extra);
      ASSERT_TRUE(pepenet_social::check_tx_social_validity(tx));
      pepenet_social::ibool r = get_and_verify_post_from_tx_extra(tx_extra_post, tx.extra);
      ASSERT_TRUE(r.b);
      ASSERT_TRUE(tx_extra_post.has_value());
      ASSERT_TRUE(tx_extra_post.value().dumpToBinary(post_bytes_out).b);
      ASSERT_EQ(post_bytes_in, post_bytes_out);
    }
  }