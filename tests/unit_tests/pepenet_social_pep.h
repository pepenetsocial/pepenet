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
#include <string>

const std::string VALID_PEP_ARGS_01 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1"
    }
	})";
const std::string VALID_PEP_ARGS_02 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "sk_seed": "123456",
      "post_pk": true
    }
	})";
const std::string VALID_PEP_ARGS_03 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true
    }
	})";
const std::string VALID_PEP_ARGS_04 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": false
    }
	})";
const std::string VALID_PEP_ARGS_05 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    }
	})";
const std::string VALID_PEP_ARGS_06 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good"
    }
	})";
const std::string VALID_PEP_ARGS_07 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })";
const std::string VALID_PEP_ARGS_08 = R"({
    "pep_args": {
      "msg": "pepe has a good day",
      "pseudonym": "pepe1",
      "sk_seed": "123456",
      "post_pk": true,
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
      "pepetag": "good",
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })";

#define VALID_PEP_ARGS \
VALID_PEP_ARGS_01,\
VALID_PEP_ARGS_02,\
VALID_PEP_ARGS_03,\
VALID_PEP_ARGS_04,\
VALID_PEP_ARGS_05,\
VALID_PEP_ARGS_06,\
VALID_PEP_ARGS_07,\
VALID_PEP_ARGS_08\

const std::string INVALID_PEP_ARGS_01 = R"({
    "pep_args": {
    }
  })";
const std::string INVALID_PEP_ARGS_02 = R"({
    "pep_args": {
      "msg": "",
    }
  })";
const std::string INVALID_PEP_ARGS_03 = R"({
    "pep_args": {
      "pseudonym": ""
    }
  })";
const std::string INVALID_PEP_ARGS_04 = R"({
    "pep_args": {
      "pseudonym": "goodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgoodgood"
    }
  })";
const std::string INVALID_PEP_ARGS_05 = R"({
    "pep_args": {
      "sk_seed": ""
    }
  })";
const std::string INVALID_PEP_ARGS_06 = R"({
    "pep_args": {
      "sk_seed": "123456"
    }
  })";
const std::string INVALID_PEP_ARGS_07 = R"({
    "pep_args": {
      "sk_seed": "123456",
      "post_pk": 1
    }
  })";
const std::string INVALID_PEP_ARGS_08 = R"({
    "pep_args": {
      "sk_seed": "123456",
      "post_pk": 0
    }
  })";
const std::string INVALID_PEP_ARGS_09 = R"({
    "pep_args": {
      "post_pk": true
    }
  })";
const std::string INVALID_PEP_ARGS_10 = R"({
    "pep_args": {
      "tx_ref": "a665a45920422f"
    }
  })";
const std::string INVALID_PEP_ARGS_11 = R"({
    "pep_args": {
      "tx_ref": "a665a45920422a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3f"
    }
  })";
const std::string INVALID_PEP_ARGS_12 = R"({
    "pep_args": {
      "tx_ref": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27aeK"
    }
  })";
const std::string INVALID_PEP_ARGS_13 = R"({
    "pep_args": {
      "pepetag": ""
    }
  })";
const std::string INVALID_PEP_ARGS_14 = R"({
    "pep_args": {
      "pepetag": "pepepepeeppepepepepppepepepeeppepepepepp"
    }
  })";
const std::string INVALID_PEP_ARGS_15 = R"({
    "pep_args": {
      "pepetag": "pepepepeeppepepepepppepepepeeppepepepepp"
    }
  })";
const std::string INVALID_PEP_ARGS_16 = R"({
    "pep_args": {
      "donation_address": ""
    }
  })";
const std::string INVALID_PEP_ARGS_17 = R"({
    "pep_args": {
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"
    }
  })";
const std::string INVALID_PEP_ARGS_18 = R"({
    "pep_args": {
      "donation_address": "P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed9"
    }
  })";

#define INVALID_PEP_ARGS \
INVALID_PEP_ARGS_01,\
INVALID_PEP_ARGS_02,\
INVALID_PEP_ARGS_03,\
INVALID_PEP_ARGS_04,\
INVALID_PEP_ARGS_05,\
INVALID_PEP_ARGS_06,\
INVALID_PEP_ARGS_07,\
INVALID_PEP_ARGS_08,\
INVALID_PEP_ARGS_09,\
INVALID_PEP_ARGS_10,\
INVALID_PEP_ARGS_11,\
INVALID_PEP_ARGS_12,\
INVALID_PEP_ARGS_13,\
INVALID_PEP_ARGS_14,\
INVALID_PEP_ARGS_15,\
INVALID_PEP_ARGS_16,\
INVALID_PEP_ARGS_17,\
INVALID_PEP_ARGS_18\

