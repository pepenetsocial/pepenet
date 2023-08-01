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

#pragma once

#include "lzma.h"
#include "crypto/crypto.h"
#include "../contrib/epee/include/hex.h"
#include "../contrib/epee/include/misc_log_ex.h"
#include "../contrib/epee/include/string_tools.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include <iostream>
#include <vector>
#include <pepenet_social.pb.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rapidjson/schema.h>
#include <boost/format.hpp>

#define INFO_NULLOPT boost::optional<std::string>()

namespace pepenet_social {

  typedef std::string bytes;

  struct ibool {
    bool b;
    boost::optional<std::string> info;
  };

  class social_args{
    public:
      ibool loadJson(const std::string& json);
      ibool loadJsonSchema(const std::string& json);
      ibool validate() { return validateJsonSchema(); };
      virtual ibool loadFromJson() = 0;
    protected:
      ibool validateJsonSchema();
      rapidjson::Document m_json;
      rapidjson::Document m_schema;
      bool m_valid_args = false;
  };

  template <typename SocialProto>
  class social_feature
  {
    public:
      virtual bool validate() = 0;
      virtual bool loadFromProto() = 0;
      virtual bool dumpToProto() = 0;
      virtual bool loadFromBinary(const bytes& bytes) = 0;
      virtual bool dumpToBinary(bytes& bytes) = 0;
      virtual bool dumpToJsonStr(std::string& json) = 0;
    protected:
      SocialProto m_proto;
  };

  bool lzma_compress_msg(const std::string& msg, std::string& out);
  bool lzma_decompress_msg(const std::string& msg, std::string& out);
  bool secret_key_from_seed(const std::string& sk_seed, crypto::secret_key& sk);
  //use crypto::secret_key_to_public_key
  bool sign_msg(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk, const crypto::secret_key& sk);
  bool check_msg_sig(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk);

  bool add_pep_to_tx_extra(const pepenet_social::pep_args pep_args, std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err);
  bool add_post_to_tx_extra(const pepenet_social::post_args post_args, std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err);

  bool get_and_verify_pep_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::pep>& pep, const std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err);
  bool get_and_verify_post_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::post>& post, const std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err);
  bool check_tx_social_validity(const cryptonote::transaction& tx);
}

#ifndef CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L
#define CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L(expr, fail_ret_val, l, message)   do{if(!(expr)) {err = message; LOG_PRINT_L##l(message); /*LOCAL_ASSERT(expr);*/ return fail_ret_val;};}while(0)
#endif

#ifndef CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1
#define CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(expr, fail_ret_val, message) CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L(expr, fail_ret_val, 1, message)
#endif