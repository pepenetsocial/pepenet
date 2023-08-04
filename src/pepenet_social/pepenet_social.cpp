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

  ibool social_args::loadJson(const std::string& json)
  {
    if (m_json.Parse(json.c_str()).HasParseError())
    {
      return { false, INFO_NULLOPT };
    }
    m_json_loaded = true;
    return { true, INFO_NULLOPT };
  }

  ibool social_args::loadJsonSchema()
  {
    if (m_schema.Parse(m_json_schema_str.c_str()).HasParseError())
    {
      return { false, INFO_NULLOPT };
    }
    m_schema_loaded = true;
    return { true, INFO_NULLOPT };
  }

  ibool social_args::validateJsonSchema()
  {
    if (!m_json_loaded || !m_schema_loaded)
    {
      return ibool{ false, std::string("Schema and json have to be loaded before schema validation") };
    }
    rapidjson::SchemaDocument schema(m_schema);
    rapidjson::SchemaValidator validator(schema);
    if (!m_json.Accept(validator))
    {
      // Input JSON is invalid according to the schema
      // Output diagnostic information
      rapidjson::StringBuffer sb;
      validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);

      std::string info = "";
      info += (boost::format("Invalid schema: %s\nInvalid keyword: %s\n") % sb.GetString() % validator.GetInvalidSchemaKeyword()).str();
      sb.Clear();
      validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
      info += (boost::format("Invalid document: %s\n") % sb.GetString()).str();

      return ibool{ false, info };
    }
    
    m_schema_valid = true;
    return ibool{ true, INFO_NULLOPT };
  }

  bool lzma_compress_msg(const std::string& msg, std::string& out)
  {
    const uint8_t* msg_ = (const uint8_t*)msg.c_str();
    std::size_t msg_len = strlen(msg.c_str());
    uint32_t compressed_size;
    auto compressedBlob = lzmaCompress(msg_, msg_len, &compressed_size);
    if (compressedBlob)
      out = std::string((char*)(compressedBlob.get()), compressed_size);
    return (bool)compressedBlob;
  }

  bool lzma_decompress_msg(const std::string& msg, std::string& out)
  {
    const uint8_t* msg_ = (const uint8_t*)msg.c_str();
    std::size_t msg_len = msg.size();
    uint32_t decompressed_size;
    auto decompressedBlob = lzmaDecompress(msg_, msg_len, &decompressed_size);
    if (decompressedBlob)
      out = std::string((char*)(decompressedBlob.get()), decompressed_size);
    return (bool)decompressedBlob;
  }

  bool secret_key_from_seed(const std::string& sk_seed, crypto::secret_key& sk)
  {
    try
    {
      crypto::hash_to_scalar(sk_seed.data(), sk_seed.size(), sk);
    }
    catch (const std::exception& ex)
    {
      LOG_ERROR("Exception at [secret_key_from_seed], what=" << ex.what());
      return false;
    }
    return true;
  }

  bool sign_msg(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk, const crypto::secret_key& sk)
  {
    crypto::hash prefix_hash;
    try
    {
      crypto::cn_fast_hash(msg.data(), msg.size(), prefix_hash);
      crypto::generate_signature(prefix_hash, pk, sk, sig);
    }
    catch (const std::exception& ex)
    {
      LOG_ERROR("Exception at [sign_msg], what=" << ex.what());
      return false;
    }
    return true;
  }

  bool check_msg_sig(const std::string& msg, crypto::signature& sig, const crypto::public_key& pk)
  {
    crypto::hash prefix_hash;
    bool r;
    try
    {
      crypto::cn_fast_hash(msg.data(), msg.size(), prefix_hash);
      r = crypto::check_signature(prefix_hash, pk, sig);
    }
    catch (const std::exception& ex)
    {
      LOG_ERROR("Exception at [sign_msg], what=" << ex.what());
      return false;
    }
    return r;
  }

  bool to_bytes(const crypto::signature& sig, bytes& b)
  {
    b = bytes(sig.c.data, 32) + bytes(sig.r.data, 32);
    return true;
  }
  bool from_bytes(crypto::signature& sig, const bytes& b)
  {
    if (b.size() != 64)
    {
      return true;
    }
    try
    {
      std::memcpy(&sig.c.data, b.data(), 32);
      std::memcpy(&sig.r.data, b.data() + 32, 32);
    }
    catch (const std::exception& e)
    {
      return false;
    }
    return true;
  }
  bool to_bytes(const crypto::hash& hash, bytes& b)
  {
    b = bytes(hash.data, 32);
    return true;
  }
  bool from_bytes(crypto::hash& hash, const bytes& b)
  {
    if (b.size() != 32)
    {
      return true;
    }
    try
    {
      std::memcpy(&hash.data, b.data(), 32);
    }
    catch (const std::exception& e)
    {
      return false;
    }
    return true;
  }
  bool to_bytes(const crypto::public_key& pk, bytes& b)
  {
    b = bytes(pk.data, 32);
    return true;
  }
  bool from_bytes(crypto::public_key& pk, const bytes& b)
  {
    if (b.size() != 32)
    {
      return true;
    }
    try
    {
      std::memcpy(&pk.data, b.data(), 32);
    }
    catch (const std::exception& e)
    {
      return false;
    }
    return true;
  }
  
  //ibool get_and_verify_post_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::post>& pep, const std::vector<uint8_t>& tx_extra);

  bool check_tx_social_validity(const cryptonote::transaction& tx)
  {
    /*
    boost::optional<pepenet_social::pep> pep;
    boost::optional<pepenet_social::post> post;
    boost::optional<crypto::public_key> null_pk;
    boost::optional<std::string> err;
    bool post_v = pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra, err);
    bool pep_v = pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra, err);

    if ((post_v && post.has_value()) || (pep_v && pep.has_value())) //valid pep or valid post
      return true;
    if ((!post_v && post.has_value()) && (!pep_v && pep.has_value())) //missing pep and missing post
      return true;
    //other cases are invalid
    return false;
  */
    return true;
  }

}