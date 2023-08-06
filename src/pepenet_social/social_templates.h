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

#include "social_helpers.h"
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rapidjson/schema.h>
#include <boost/format.hpp>
#include "pepenet_social.pb.h"

namespace pepenet_social {

  class social_args {
    public:
    ibool loadJson(const std::string& json);
    virtual ibool validate() { return { m_valid_args , INFO_NULLOPT }; };
    virtual ibool loadArgsFromJson() = 0;
    protected:
    virtual void setSchema() = 0;
    rapidjson::Document m_json;
    bool m_json_schema_str_loaded = false;
    bool m_schema_valid = false;
    std::string m_json_schema_str;
    bool m_valid_args = false;
  };

  template <typename SocialProto, typename SocialArgs>
  class social_feature
  {
    public:
    virtual ibool validate() = 0;
    virtual ibool loadFromSocialArgs(SocialArgs const& args) = 0;
    //virtual ibool dumpToJsonStr(std::string& json) = 0;
    ibool loadFromBinary(const bytes& bytes)
    {
      //load to proto
      bool success = false;
      try
      {
        success = m_proto.ParseFromString(bytes);
      }
      catch (std::exception const& e)
      {
        return ibool{ success, std::string("failed to load proto from bytes. exception: ") + e.what() };
      }
      //load from proto
      ibool r = loadFromProto();
      if (!r.b)
      {
        return r;
      }
      r = validate();
      if (!r.b)
      {
        return r;
      }
      //done
      return ibool{ success, INFO_NULLOPT };
    }
    ibool dumpToBinary(bytes& bytes)
    {
      if (!m_valid || !m_loaded)
      {
        return ibool{ false, std::string("first load and validate social feature") };
      }
      //first call dump to proto
      ibool r = dumpToProto();
      if (!r.b)
      {
        return r;
      }
      //dump to binary after variables are set in proto
      bool success = false;
      try
      {
        success = m_proto.SerializeToString(&bytes);
      }
      catch (std::exception const& e)
      {
        return ibool{ success, std::string("failed to serialize proto to bytes. exception: ") + e.what() };
      }
      return ibool{ success, INFO_NULLOPT };
    }
    protected:
    virtual ibool dumpToProto() = 0;
    virtual ibool loadFromProto() = 0;
    SocialProto m_proto;
    bool m_valid = false;
    bool m_loaded = false;
  };

}