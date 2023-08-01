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

#include "pepenet_social.h"

class post_args : public social_args
{
  friend class post;
  private:
  std::string m_title;
  std::string m_msg;
  boost::optional<std::string> m_pseudonym;
  boost::optional<std::string> m_sk_seed;
  bool m_post_pk;
  boost::optional<crypto::hash> m_tx_ref;
  boost::optional<std::string> m_pepetag;
  boost::optional<std::string> m_donation_address;
};

class post : public social_feature
{
  public:
  post(const post_args& args);
  bool validate();
  bool loadFromProto();
  bool dumpToProto();
  bool loadFromBinary(const bytes& bytes);
  bool dumpToBinary(bytes& bytes);
  bool dumpToJsonStr(std::string& json);
  private:
  std::string m_title;
  std::string m_msg;
  boost::optional<std::string> m_pseudonym;
  boost::optional<crypto::public_key> m_pk;
  boost::optional<crypto::signature> m_sig;
  boost::optional<crypto::hash> m_tx_ref;
  boost::optional<std::string> m_pepetag;
  boost::optional<std::string> m_donation_address;
  pepenet_social_protos::post m_proto;
};