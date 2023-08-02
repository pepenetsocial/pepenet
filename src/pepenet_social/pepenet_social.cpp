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

  bool add_pep_to_tx_extra(const pepenet_social::pep_args pep_args, std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err)
  {
    err.reset();
    std::string lzma_pep;
    CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(pepenet_social::lzma_compress_msg(pep_args.msg, lzma_pep), false, "failed to compress pep");
    //get keys
    crypto::public_key pk;
    crypto::secret_key sk;
    if (pep_args.sk_seed.has_value())
    {
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(pepenet_social::secret_key_from_seed(pep_args.sk_seed.value(), sk), false, "failed to generate sk");
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(crypto::secret_key_to_public_key(sk, pk), false, "failed to generate pk from sk");
    }
    crypto::signature full_pep_sig;
    //contruct full content for signing
    if (pep_args.sk_seed.has_value())
    {
      std::string tr_s = pep_args.tx_ref.has_value() ? std::string(pep_args.tx_ref.value().data, 32) : "";
      std::string pk_s = (pep_args.sk_seed.has_value() && pep_args.post_pk) ? std::string(pk.data, 32) : "";
      std::string full_pep = pep_args.msg + pep_args.pseudonym.value_or("") + tr_s + pk_s
        + pep_args.pepetag.value_or("") + pep_args.donation_address.value_or("");
      pepenet_social::sign_msg(full_pep, full_pep_sig, pk, sk);
    }
    //add all fields to extra
    CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_lzma_pep_to_tx_extra(tx_extra, lzma_pep), false, "failed to add pep to tx_extra");
    if (pep_args.pseudonym.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_pseudonym_to_tx_extra(tx_extra, pep_args.pseudonym.value()), false, "failed to add pseudonym to tx_extra");
    if ((pep_args.sk_seed.has_value() && pep_args.post_pk))
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_eddsa_pubkey_to_tx_extra(tx_extra, pk), false, "failed to add pk to tx_extra");
    if (pep_args.sk_seed.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_eddsa_signature_to_tx_extra(tx_extra, full_pep_sig), false, "failed to add full pep signature to tx_extra");
    if (pep_args.tx_ref.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_tx_reference_to_tx_extra(tx_extra, pep_args.tx_ref.value()), false, "failed to add tx reference to tx_extra");
    if (pep_args.pepetag.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_pepetag_to_tx_extra(tx_extra, pep_args.pepetag.value()), false, "failed to add pepetag to tx_extra");
    if (pep_args.donation_address.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_donation_address_to_tx_extra(tx_extra, pep_args.donation_address.value()), false, "failed to add donation address to tx_extra");
    //if we are here its ok.
    return true;
  }

  bool add_post_to_tx_extra(const pepenet_social::post_args post_args, std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err)
  {
    err.reset();
    std::string lzma_post;
    CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(pepenet_social::lzma_compress_msg(post_args.msg, lzma_post), false, "failed to compress pep");
    //get keys
    crypto::public_key pk;
    crypto::secret_key sk;
    if (post_args.sk_seed.has_value())
    {
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(pepenet_social::secret_key_from_seed(post_args.sk_seed.value(), sk), false, "failed to generate sk");
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(crypto::secret_key_to_public_key(sk, pk), false, "failed to generate pk from sk");
    }
    crypto::signature full_post_sig;
    //contruct full content for signing
    if (post_args.sk_seed.has_value())
    {
      std::string tr_s = post_args.tx_ref.has_value() ? std::string(post_args.tx_ref.value().data, 32) : "";
      std::string pk_s = (post_args.sk_seed.has_value() && post_args.post_pk) ? std::string(pk.data, 32) : "";
      std::string full_pep = post_args.msg + post_args.title + post_args.pseudonym.value_or("") + tr_s + pk_s
        + post_args.pepetag.value_or("") + post_args.donation_address.value_or("");
      pepenet_social::sign_msg(full_pep, full_post_sig, pk, sk);
    }
    //add all fields to extra
    CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_lzma_post_to_tx_extra(tx_extra, lzma_post), false, "failed to add pep to tx_extra");
    CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_post_title_to_tx_extra(tx_extra, post_args.title), false, "failed to add post title to tx_extra");
    if (post_args.pseudonym.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_pseudonym_to_tx_extra(tx_extra, post_args.pseudonym.value()), false, "failed to add pseudonym to tx_extra");
    if ((post_args.sk_seed.has_value() && post_args.post_pk))
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_eddsa_pubkey_to_tx_extra(tx_extra, pk), false, "failed to add pk to tx_extra");
    if (post_args.sk_seed.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_eddsa_signature_to_tx_extra(tx_extra, full_post_sig), false, "failed to add full pep signature to tx_extra");
    if (post_args.tx_ref.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_tx_reference_to_tx_extra(tx_extra, post_args.tx_ref.value()), false, "failed to add tx reference to tx_extra");
    if (post_args.pepetag.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_pepetag_to_tx_extra(tx_extra, post_args.pepetag.value()), false, "failed to add pepetag to tx_extra");
    if (post_args.donation_address.has_value())
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(cryptonote::add_donation_address_to_tx_extra(tx_extra, post_args.donation_address.value()), false, "failed to add donation address to tx_extra");
    //if we are here its ok.
    return true;
  }

  bool get_and_verify_pep_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::pep>& pep, const std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err)
  {
    err.reset();
    //init pep optional
    pep = pepenet_social::pep();
    //reject if post features are present (post title, lzma post) - peps don't have titles and posts!
    std::string title, lzma_post;
    if (cryptonote::get_post_title_from_tx_extra(tx_extra, title) || cryptonote::get_lzma_post_from_tx_extra(tx_extra, lzma_post))
    {
      err = "post features present";
      pep.reset();
      return false;
    }
    std::string lzma_pep;
    bool pep_missing = !cryptonote::get_lzma_pep_from_tx_extra(tx_extra, lzma_pep);
    if (!pep_missing)
    {
      bool decomp = pepenet_social::lzma_decompress_msg(lzma_pep, pep.value().msg);
      if (!decomp)
        pep.reset(); //decompression failed - invalid tx
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(decomp, false, "failed to decompress lzma pep from tx_extra");
    }
    cryptonote::get_pseudonym_from_tx_extra(tx_extra, pep.value().pseudonym);
    bool pk_present = cryptonote::get_eddsa_pubkey_from_tx_extra(tx_extra, pep.value().pk);
    bool sig_present = cryptonote::get_eddsa_signature_from_tx_extra(tx_extra, pep.value().sig);
    if ((pk_present && !sig_present)) // if pk is present, sig has to be too!
    {
      err = "public key present without signature";
      pep.reset(); //invalid tx extra
      return false;
    }
    cryptonote::get_tx_reference_from_tx_extra(tx_extra, pep.value().tx_ref);
    cryptonote::get_pepetag_from_tx_extra(tx_extra, pep.value().pepetag);
    cryptonote::get_donation_address_from_tx_extra(tx_extra, pep.value().donation_address);
    //check if tx_extra is valid
    if (pep_missing && (pep.value().pseudonym.has_value() || pep.value().pk.has_value() || pep.value().sig.has_value() || pep.value().tx_ref.has_value() || pep.value().pepetag.has_value() || pep.value().donation_address.has_value()))
    {
      err = "pep msg is not present while one or more pep fields are present";
      pep.reset(); //invalid tx - pep tag is not present while one or more pep fields are present 
      return false;
    }
    else if (pep_missing) //valid tx - just without a pep
      return false;
    //construct full pep for sig. verification
    
    if (pep.value().pk.has_value())
    {
      std::string tr_s = pep.value().tx_ref.has_value() ? std::string(pep.value().tx_ref.value().data, 32) : "";
      std::string pk_s = std::string(pep.value().pk.value().data, 32);
      std::string full_pep = pep.value().msg + pep.value().pseudonym.value_or("") + tr_s + pk_s
        + pep.value().pepetag.value_or("") + pep.value().donation_address.value_or("");
      bool valid = pepenet_social::check_msg_sig(full_pep, pep.value().sig.value(), pep.value().pk.value());
      if (!valid)
      {
        err = "invalid pep signature";
        pep.reset(); //invalid tx - pep signature is invalid !
      }
      return valid;
    }
    else if (ver_pk.has_value())
    {
      std::string tr_s = pep.value().tx_ref.has_value() ? std::string(pep.value().tx_ref.value().data, 32) : "";
      std::string pk_s = "";
      std::string full_pep = pep.value().msg + pep.value().pseudonym.value_or("") + tr_s + pk_s
        + pep.value().pepetag.value_or("") + pep.value().donation_address.value_or("");
      bool valid = pepenet_social::check_msg_sig(full_pep, pep.value().sig.value(), ver_pk.value());
      if (!valid)
      {
        err = "invalid pep signature";
        pep.reset(); //invalid tx - pep signature is invalid !
      }
      return valid;
    }
    return true;
  }
  
  bool get_and_verify_post_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::post>& post, const std::vector<uint8_t>& tx_extra, boost::optional<std::string>& err)
  {
    err.reset();
    //init post optional
    post = pepenet_social::post();
    //reject if pep features are present (lzma pep) - posts don't have peps!
    std::string lzma_pep;
    if (cryptonote::get_lzma_pep_from_tx_extra(tx_extra, lzma_pep))
    {
      err = "pep features present";
      post.reset();
      return false;
    }
    std::string lzma_post;
    bool post_missing = !cryptonote::get_lzma_post_from_tx_extra(tx_extra, lzma_post);
    bool title_missing = !cryptonote::get_post_title_from_tx_extra(tx_extra, post.value().title);
    if (!post_missing)
    {
      bool decomp = pepenet_social::lzma_decompress_msg(lzma_post, post.value().msg);
      if (!decomp)
        post.reset(); //decompression failed - invalid tx
      CHECK_AND_NO_ASSERT_MES_SOCIAL_ERR_L1(decomp, false, "failed to decompress lzma post from tx_extra");
    }
    cryptonote::get_pseudonym_from_tx_extra(tx_extra, post.value().pseudonym);
    bool pk_present = cryptonote::get_eddsa_pubkey_from_tx_extra(tx_extra, post.value().pk);
    bool sig_present = cryptonote::get_eddsa_signature_from_tx_extra(tx_extra, post.value().sig);
    if ((pk_present && !sig_present)) // if pk is present, sig has to be too!
    {
      err = "public key present without signature";
      post.reset(); //invalid tx extra
      return false;
    }
    cryptonote::get_tx_reference_from_tx_extra(tx_extra, post.value().tx_ref);
    cryptonote::get_pepetag_from_tx_extra(tx_extra, post.value().pepetag);
    cryptonote::get_donation_address_from_tx_extra(tx_extra, post.value().donation_address);
    //check if tx_extra is valid
    if ((post_missing || title_missing) && (post.value().pseudonym.has_value() || post.value().pk.has_value() || post.value().sig.has_value() || post.value().tx_ref.has_value() || post.value().pepetag.has_value() || post.value().donation_address.has_value()))
    {
      err = "post msg or post title are not present while one or more post fields are present";
      post.reset(); //invalid tx - post or title tag is not present while one or more post fields are present 
      return false;
    }
    else if (post_missing && title_missing) //valid tx - just without a post
      return false;
    //construct full post for sig. verification
    if (post.value().pk.has_value())
    {
      std::string tr_s = post.value().tx_ref.has_value() ? std::string(post.value().tx_ref.value().data, 32) : "";
      std::string pk_s = std::string(post.value().pk.value().data, 32);
      std::string full_post = post.value().msg + post.value().title + post.value().pseudonym.value_or("") + tr_s + pk_s
        + post.value().pepetag.value_or("") + post.value().donation_address.value_or("");
      bool valid = pepenet_social::check_msg_sig(full_post, post.value().sig.value(), post.value().pk.value());
      if (!valid)
      {
        err = "invalid post signature";
        post.reset(); //invalid tx - post signature is invalid !
      }
      return valid;
    }
    else if (ver_pk.has_value())
    {
      std::string tr_s = post.value().tx_ref.has_value() ? std::string(post.value().tx_ref.value().data, 32) : "";
      std::string pk_s = "";
      std::string full_pep = post.value().msg + post.value().title + post.value().pseudonym.value_or("") + tr_s + pk_s
        + post.value().pepetag.value_or("") + post.value().donation_address.value_or("");
      bool valid = pepenet_social::check_msg_sig(full_pep, post.value().sig.value(), ver_pk.value());
      if (!valid)
      {
        err = "invalid post signature";
        post.reset(); //invalid tx - post signature is invalid !
      }
      return valid;
    }
    return true;
  }

  bool check_tx_social_validity(const cryptonote::transaction& tx)
  {
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
  }

}