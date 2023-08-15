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

#include "pepenet_social.h"

namespace pepenet_social {

bool check_tx_social_validity(const cryptonote::transaction& tx)
{
  if (!no_duplicate_social_features(tx))
  {
    return false;
  }
  //TODO: make this even more scalable
  boost::optional<pepenet_social::pep> pep;
  boost::optional<pepenet_social::post> post;
  {
    ibool r = pepenet_social::get_and_verify_post_from_tx_extra(post, tx.extra);
    if (r.b != post.has_value())
      return false;
  }
  {
    ibool r = pepenet_social::get_and_verify_pep_from_tx_extra(pep, tx.extra);
    if (r.b != pep.has_value())
      return false;
  }
  return true;
}

bool no_duplicate_social_features(const cryptonote::transaction& tx)
  {
    std::vector<cryptonote::tx_extra_field> tx_extra_fields;
    cryptonote::parse_tx_extra(tx.extra, tx_extra_fields);

    size_t num_of_social_feature_fields = 0;
    for (auto field : tx_extra_fields)
    {
      if (field.type() == typeid(cryptonote::tx_extra_social_feature))
      {
        ++num_of_social_feature_fields;
      }
    }
    return num_of_social_feature_fields <= 1;
  }

ibool add_pep_to_tx_extra(pepenet_social::pep& pep, std::vector<uint8_t>& tx_extra)
{
  CHECK_AND_ASSERT_RETURN_IBOOL(pep.validate().b, "invalid pep, failed to add to tx_extra");
  bytes proto_bytes, compressed_proto_bytes;
  CHECK_AND_ASSERT_RETURN_IBOOL(pep.dumpToBinary(proto_bytes).b, "failed to serialize pep to binary");
  //compress
  CHECK_AND_ASSERT_RETURN_IBOOL(lzma_compress_msg(proto_bytes, compressed_proto_bytes), "failed to compress pep proto bytes");
  CHECK_AND_ASSERT_RETURN_IBOOL(cryptonote::add_social_feature_to_tx_extra(tx_extra, compressed_proto_bytes, PEP_SOCIAL_FEATURE_TAG), "failed to add pep bytes to tx extra");
  return { true, INFO_NULLOPT };
}


ibool get_and_verify_pep_from_tx_extra(boost::optional<pepenet_social::pep>& pep, const std::vector<uint8_t>& tx_extra)
{
  size_t feature_id;
  bytes proto_bytes, compressed_proto_bytes;
  CHECK_AND_ASSERT_RETURN_IBOOL(cryptonote::get_social_feature_from_tx_extra(tx_extra, compressed_proto_bytes, feature_id), "failed to get pep bytes from tx_extra");
  CHECK_AND_ASSERT_RETURN_IBOOL(feature_id == PEP_SOCIAL_FEATURE_TAG, "pep not found in tx extra");
  //decompress
  pep = pepenet_social::pep();
  CHECK_AND_ASSERT_RETURN_IBOOL(lzma_decompress_msg(compressed_proto_bytes, proto_bytes), "failed to decompress pep proto bytes");
  CHECK_AND_ASSERT_RETURN_IBOOL(pep.value().loadFromBinary(proto_bytes).b, "failed to load pep from binary");
  return { true, INFO_NULLOPT };
}

ibool add_post_to_tx_extra(pepenet_social::post& post, std::vector<uint8_t>& tx_extra)
{
  CHECK_AND_ASSERT_RETURN_IBOOL(post.validate().b, "invalid post, failed to add to tx_extra");
  bytes proto_bytes, compressed_proto_bytes;
  CHECK_AND_ASSERT_RETURN_IBOOL(post.dumpToBinary(proto_bytes).b, "failed to serialize post to binary");
  //compress
  CHECK_AND_ASSERT_RETURN_IBOOL(lzma_compress_msg(proto_bytes, compressed_proto_bytes), "failed to compress post proto bytes");
  CHECK_AND_ASSERT_RETURN_IBOOL(cryptonote::add_social_feature_to_tx_extra(tx_extra, compressed_proto_bytes, POST_SOCIAL_FEATURE_TAG), "failed to add post bytes to tx extra");
  return { true, INFO_NULLOPT };
}


ibool get_and_verify_post_from_tx_extra(boost::optional<pepenet_social::post>& post, const std::vector<uint8_t>& tx_extra)
{
  size_t feature_id;
  bytes proto_bytes, compressed_proto_bytes;
  CHECK_AND_ASSERT_RETURN_IBOOL(cryptonote::get_social_feature_from_tx_extra(tx_extra, compressed_proto_bytes, feature_id), "failed to get post bytes from tx_extra");
  CHECK_AND_ASSERT_RETURN_IBOOL(feature_id == POST_SOCIAL_FEATURE_TAG, "post not found in tx extra");
  //decompress
  post = pepenet_social::post();
  CHECK_AND_ASSERT_RETURN_IBOOL(lzma_decompress_msg(compressed_proto_bytes, proto_bytes), "failed to decompress post proto bytes");
  CHECK_AND_ASSERT_RETURN_IBOOL(post.value().loadFromBinary(proto_bytes).b, "failed to load post from binary");
  return { true, INFO_NULLOPT };
}

}
