#pragma once

#include "lzma.h"
#include "crypto/crypto.h"
#include "../contrib/epee/include/hex.h"
#include "../contrib/epee/include/misc_log_ex.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include <iostream>
#include <vector>
#include <optional>

namespace pepenet_social {

  struct pep_args {
    std::string msg;
    boost::optional<std::string> pseudonym;
    boost::optional<std::string> sk_seed;
    bool post_pk;
    boost::optional<crypto::hash> tx_ref;
    boost::optional<std::string> pepetag;
    boost::optional<std::string> donation_address;
  };

  struct post_args : public pep_args {
    std::string title;
  };

  struct pep {
    std::string msg;
    boost::optional<std::string> pseudonym;
    boost::optional<crypto::public_key> pk;
    boost::optional<crypto::signature> sig;
    boost::optional<crypto::hash> tx_ref;
    boost::optional<std::string> pepetag;
    boost::optional<std::string> donation_address;
  };

  struct post : public pep {
    std::string title;
  };

  typedef std::logic_error tx_social_error;

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