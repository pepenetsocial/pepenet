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

#include "social_templates.h"

namespace pepenet_social {

  ibool social_args::loadJson(const std::string& json)
  {
    setSchema();
    //parse document
    if (m_json.Parse(json.data()).HasParseError())
    {
      return FALSE_IBOOL("the input is not a valid JSON.");
    }
    //parse schema
    if (!m_json_schema_str_loaded)
    {
      return FALSE_IBOOL("json schema string is not loaded");
    }

    rapidjson::Document sd;
    if (sd.Parse(m_json_schema_str.data()).HasParseError())
    {
      return FALSE_IBOOL("the schema is not a valid JSON.");
    }
    rapidjson::SchemaDocument schema(sd); // Compile a Document to SchemaDocument
    // sd is no longer needed here.
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

      m_schema_valid = false;
      return FALSE_IBOOL(info);
    }
    m_schema_valid = true;
    return { true, INFO_NULLOPT };
  }
}