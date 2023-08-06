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

  /*
ibool add_pep_to_tx_extra(const pepenet_social::pep& pep, std::vector<uint8_t>& tx_extra)
{
  bytes lzma_pep;
  pepenet_social::pep p = pep;
  ibool r = p.dumpToBinary(lzma_pep);
  if (!r.b)
  {
    return r;
  }
  if (!cryptonote::add_lzma_pep_to_tx_extra(tx_extra, lzma_pep))
  {
    return FALSE_IBOOL("failed to add pep to tx_extra") };
  }
  return ibool{ true, INFO_NULLOPT };
}

ibool get_and_verify_pep_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::pep>& pep, const std::vector<uint8_t>& tx_extra)
{
  //init pep optional
  pep = pepenet_social::pep();
  std::string lzma_pep;
  bool pep_missing = !cryptonote::get_lzma_pep_from_tx_extra(tx_extra, lzma_pep);
  if (!pep_missing)
  {
    bytes pep_proto_bytes;
    bool decomp = pepenet_social::lzma_decompress_msg(lzma_pep, pep_proto_bytes);
    if (!decomp)
    {
      pep.reset(); //decompression failed - invalid tx
      return FALSE_IBOOL("failed to decompress lzma pep from tx_extra") };
    }
    ibool r = pep.value().loadFromBinary(pep_proto_bytes);
    if (!r.b)
    {
      return FALSE_IBOOL("failed to load pep proto from bytes in tx_extra") };
    }
    r = pep.value().validate(ver_pk.value());
    if (!r.b)
    {
      return r;
    }
    return ibool{ true, INFO_NULLOPT };
  }
  else
  {
    pep.reset();
  }
  return { true, INFO_NULLOPT };
}
*/

}