#include "pepenet_social.h"
namespace pepenet_social {
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

  bool add_pep_to_tx_extra(const pepenet_social::pep_args pep_args, std::vector<uint8_t>& tx_extra)
  {
    std::string lzma_pep;
    CHECK_AND_NO_ASSERT_MES_L1(pepenet_social::lzma_compress_msg(pep_args.msg, lzma_pep), false, "failed to compress pep");
    //get keys
    crypto::public_key pk;
    crypto::secret_key sk;
    if (pep_args.sk_seed.has_value())
    {
      CHECK_AND_NO_ASSERT_MES_L1(pepenet_social::secret_key_from_seed(pep_args.sk_seed.value(), sk), false, "failed to generate sk");
      CHECK_AND_NO_ASSERT_MES_L1(crypto::secret_key_to_public_key(sk, pk), false, "failed to generate pk from sk");
    }
    crypto::signature full_pep_sig;
    //contruct full content for signing
    if (pep_args.sk_seed.has_value())
    {
      std::string tr_s = pep_args.tx_ref.has_value() ? std::string(pep_args.tx_ref.value().data, 32) : "";
      std::string pk_s = (pep_args.sk_seed.has_value() && pep_args.post_pk) ? std::string(pk.data, 32) : "";
      std::string full_pep = pep_args.msg + pep_args.pseudonym.value_or("") + tr_s + pk_s;
      pepenet_social::sign_msg(full_pep, full_pep_sig, pk, sk);
    }
    //add all fields to extra
    CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_lzma_pep_to_tx_extra(tx_extra, lzma_pep), false, "failed to add pep to tx_extra");
    if (pep_args.pseudonym.has_value())
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_pseudonym_to_tx_extra(tx_extra, pep_args.pseudonym.value()), false, "failed to add pseudonym to tx_extra");
    if ((pep_args.sk_seed.has_value() && pep_args.post_pk))
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_eddsa_pubkey_to_tx_extra(tx_extra, pk), false, "failed to add pk to tx_extra");
    if (pep_args.sk_seed.has_value())
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_eddsa_signature_to_tx_extra(tx_extra, full_pep_sig), false, "failed to add full pep signature to tx_extra");
    if (pep_args.tx_ref.has_value())
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_tx_reference_to_tx_extra(tx_extra, pep_args.tx_ref.value()), false, "failed to add tx reference to tx_extra");
    //if we are here its ok.
    return true;
  }

  bool add_post_to_tx_extra(const pepenet_social::post_args post_args, std::vector<uint8_t>& tx_extra)
  {
    std::string lzma_post;
    CHECK_AND_NO_ASSERT_MES_L1(pepenet_social::lzma_compress_msg(post_args.msg, lzma_post), false, "failed to compress pep");
    //get keys
    crypto::public_key pk;
    crypto::secret_key sk;
    if (post_args.sk_seed.has_value())
    {
      CHECK_AND_NO_ASSERT_MES_L1(pepenet_social::secret_key_from_seed(post_args.sk_seed.value(), sk), false, "failed to generate sk");
      CHECK_AND_NO_ASSERT_MES_L1(crypto::secret_key_to_public_key(sk, pk), false, "failed to generate pk from sk");
    }
    crypto::signature full_post_sig;
    //contruct full content for signing
    if (post_args.sk_seed.has_value())
    {
      std::string tr_s = post_args.tx_ref.has_value() ? std::string(post_args.tx_ref.value().data, 32) : "";
      std::string pk_s = (post_args.sk_seed.has_value() && post_args.post_pk) ? std::string(pk.data, 32) : "";
      std::string full_pep = post_args.msg + post_args.title + post_args.pseudonym.value_or("") + tr_s + pk_s;
      pepenet_social::sign_msg(full_pep, full_post_sig, pk, sk);
    }
    //add all fields to extra
    CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_lzma_post_to_tx_extra(tx_extra, lzma_post), false, "failed to add pep to tx_extra");
    CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_post_title_to_tx_extra(tx_extra, post_args.title), false, "failed to add post title to tx_extra");
    if (post_args.pseudonym.has_value())
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_pseudonym_to_tx_extra(tx_extra, post_args.pseudonym.value()), false, "failed to add pseudonym to tx_extra");
    if ((post_args.sk_seed.has_value() && post_args.post_pk))
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_eddsa_pubkey_to_tx_extra(tx_extra, pk), false, "failed to add pk to tx_extra");
    if (post_args.sk_seed.has_value())
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_eddsa_signature_to_tx_extra(tx_extra, full_post_sig), false, "failed to add full pep signature to tx_extra");
    if (post_args.tx_ref.has_value())
      CHECK_AND_NO_ASSERT_MES_L1(cryptonote::add_tx_reference_to_tx_extra(tx_extra, post_args.tx_ref.value()), false, "failed to add tx reference to tx_extra");
    //if we are here its ok.
    return true;
  }

  bool get_and_verify_pep_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::pep>& pep, const std::vector<uint8_t>& tx_extra)
  {
    //init pep optional
    pep = pepenet_social::pep();
    //reject if post features are present (post title, lzma post) - peps don't have titles and posts!
    std::string title, lzma_post;
    if (cryptonote::get_post_title_from_tx_extra(tx_extra, title) || cryptonote::get_lzma_post_from_tx_extra(tx_extra, lzma_post))
    {
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
      CHECK_AND_NO_ASSERT_MES_L1(decomp, false, "failed to decompress lzma pep from tx_extra");
    }
    cryptonote::get_pseudonym_from_tx_extra(tx_extra, pep.value().pseudonym);
    bool pk_present = cryptonote::get_eddsa_pubkey_from_tx_extra(tx_extra, pep.value().pk);
    bool sig_present = cryptonote::get_eddsa_signature_from_tx_extra(tx_extra, pep.value().sig);
    if ((pk_present && !sig_present)) // if pk is present, sig has to be too!
    {
      pep.reset(); //invalid tx extra
      return false;
    }
    cryptonote::get_tx_reference_from_tx_extra(tx_extra, pep.value().tx_ref);
    //check if tx_extra is valid
    if (pep_missing && (pep.value().pseudonym.has_value() || pep.value().pk.has_value() || pep.value().sig.has_value() || pep.value().tx_ref.has_value()))
    {
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
      std::string full_pep = pep.value().msg + pep.value().pseudonym.value_or("") + tr_s + pk_s;
      bool valid = pepenet_social::check_msg_sig(full_pep, pep.value().sig.value(), pep.value().pk.value());
      if (!valid)
        pep.reset(); //invalid tx - pep signature is invalid !
      return valid;
    }
    else if (ver_pk.has_value())
    {
      std::string tr_s = pep.value().tx_ref.has_value() ? std::string(pep.value().tx_ref.value().data, 32) : "";
      std::string pk_s = "";
      std::string full_pep = pep.value().msg + pep.value().pseudonym.value_or("") + tr_s + pk_s;
      bool valid = pepenet_social::check_msg_sig(full_pep, pep.value().sig.value(), ver_pk.value());
      if (!valid)
        pep.reset(); //invalid tx - pep signature is invalid !
      return valid;
    }
    return true;
  }
  
  bool get_and_verify_post_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::post>& post, const std::vector<uint8_t>& tx_extra)
  {
    //init post optional
    post = pepenet_social::post();
    //reject if pep features are present (lzma pep) - posts don't have peps!
    std::string lzma_pep;
    if (cryptonote::get_lzma_pep_from_tx_extra(tx_extra, lzma_pep))
    {
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
      CHECK_AND_NO_ASSERT_MES_L1(decomp, false, "failed to decompress lzma post from tx_extra");
    }
    cryptonote::get_pseudonym_from_tx_extra(tx_extra, post.value().pseudonym);
    bool pk_present = cryptonote::get_eddsa_pubkey_from_tx_extra(tx_extra, post.value().pk);
    bool sig_present = cryptonote::get_eddsa_signature_from_tx_extra(tx_extra, post.value().sig);
    if ((pk_present && !sig_present)) // if pk is present, sig has to be too!
    {
      post.reset(); //invalid tx extra
      return false;
    }
    cryptonote::get_tx_reference_from_tx_extra(tx_extra, post.value().tx_ref);
    //check if tx_extra is valid
    if ((post_missing || title_missing) && (post.value().pseudonym.has_value() || post.value().pk.has_value() || post.value().sig.has_value() || post.value().tx_ref.has_value()))
    {
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
      std::string full_post = post.value().msg + post.value().title + post.value().pseudonym.value_or("") + tr_s + pk_s;
      bool valid = pepenet_social::check_msg_sig(full_post, post.value().sig.value(), post.value().pk.value());
      if (!valid)
        post.reset(); //invalid tx - post signature is invalid !
      return valid;
    }
    else if (ver_pk.has_value())
    {
      std::string tr_s = post.value().tx_ref.has_value() ? std::string(post.value().tx_ref.value().data, 32) : "";
      std::string pk_s = "";
      std::string full_pep = post.value().msg + post.value().title + post.value().pseudonym.value_or("") + tr_s + pk_s;
      bool valid = pepenet_social::check_msg_sig(full_pep, post.value().sig.value(), ver_pk.value());
      if (!valid)
        post.reset(); //invalid tx - pep signature is invalid !
      return valid;
    }
    return true;
  }

  bool check_tx_social_validity(const cryptonote::transaction& tx)
  {
    boost::optional<pepenet_social::pep> pep;
    boost::optional<pepenet_social::post> post;
    boost::optional<crypto::public_key> null_pk;
    bool post_v = pepenet_social::get_and_verify_post_from_tx_extra(null_pk, post, tx.extra);
    bool pep_v = pepenet_social::get_and_verify_pep_from_tx_extra(null_pk, pep, tx.extra);

    if ((post_v && post.has_value()) || (pep_v && pep.has_value())) //valid pep or valid post
      return true;
    if ((!post_v && post.has_value()) && (!pep_v && pep.has_value())) //missing pep and missing post
      return true;
    //other cases are invalid
    return false;
  }

}