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

#include "social_templates.h"

namespace pepenet_social {

  class post_args : public social_args
  {
    friend class post;
  public:
    virtual ibool loadArgsFromJson();
  protected:
    virtual void setSchema();
    std::string m_title;
    std::string m_msg;
    boost::optional<std::string> m_pseudonym;
    boost::optional<std::string> m_sk_seed;
    boost::optional<bool> m_post_pk;
    boost::optional<crypto::hash> m_tx_ref;
    boost::optional<std::string> m_pepetag;
    boost::optional<std::string> m_donation_address;
  };

  class post : public social_feature<pepenet_social_protos::post, post_args>
  {
  public:
    ibool validate();
    ibool validate(const boost::optional<crypto::public_key>& pk);
    ibool loadFromSocialArgs(post_args const& args);
    //ibool dumpToJsonStr(std::string& json);
  protected:
    ibool dumpToProto();
    ibool loadFromProto();
    ibool dumpBaseToProto();
    std::string m_title;
    std::string m_msg;
    boost::optional<std::string> m_pseudonym;
    boost::optional<crypto::public_key> m_pk;
    boost::optional<crypto::signature> m_sig;
    boost::optional<crypto::hash> m_tx_ref;
    boost::optional<std::string> m_pepetag;
    boost::optional<std::string> m_donation_address;
  public:
    std::string title() { return m_title; }
    std::string msg() { return m_msg; }
    boost::optional<std::string> pseudonym() { return m_pseudonym; }
    boost::optional<crypto::public_key> pk() { return m_pk; }
    boost::optional<crypto::signature> sig() { return m_sig; }
    boost::optional<crypto::hash> tx_ref() { return m_tx_ref; }
    boost::optional<std::string> pepetag() { return m_pepetag; }
    boost::optional<std::string> donation_address() { return m_donation_address; }
  };

}