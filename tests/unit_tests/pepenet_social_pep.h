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

//invalid msg
const std::string INVALID_PEP_PROTOBUF_JSON_01 = R"({"base":{"msg":"","pseudonym":"pepe1"}})";
const std::string INVALID_PEP_PROTOBUF_JSON_02 = R"({"base":{"msg":"a11e705e070bccc9d78ce594b192fa3de628e3e64fbeeab8d53ce2bcd2ecc7ecce3a05c577b155966375dd77c6b1ff93e0d53d2970f89c0161cf2bbc15eb46c3f63299b0637032b58c4a97692f666e83e5d92aa8b8d40d15843e1edf2ef763edc7e66c8b410dcc87566079ef3a00307198279f18ec54ae69f57de0017533629690dc7cd996b1f044f76c02136b42899f2eebf76c3be747113cbee030ce96392343494b2ce15cb80f427882f20fdf171ce2aae85602202974519cddf3a27b6d73dd82876d7649159d323da23f667186552a91aad844b08506a326b43ac38ab245325cd4dbef94d94d8b66ac74f2507b788b41292688072eaaf4ed2f0bbc0f5f2963fe88e24805ba8e87b9f2f7e381c6d908195776c998405662572984317ed51b4708245d892b19f75da802a08141ebe4945f32c95cf65ce52b256a9a6f69c849960c0ea58ad73cec7539c47dd8bf395c2890f74e62c91c5e5df6c2a698a86a94d2d4a5fc1e2c43e53a615ed33c25b52ec2fb9dd4a356274fe6e8f4f38b1ea8d19d1d1546f676026011cae9317c367c6c5eb2a175b1278d3b1a85ae0e48c729f0","pseudonym":"pepe1"}})";
//invalid pseudonym
const std::string INVALID_PEP_PROTOBUF_JSON_03 = R"({"base":{"msg":"pepe has a good day","pseudonym":"pepe1pepe1pepe1pepe1pepe1pepe1pepe1pepe1"}})";
//invalid pepetag
const std::string INVALID_PEP_PROTOBUF_JSON_04 = R"({"base":{"msg":"pepe has a good day","pepetag" : "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad"}})";
//invalid donation address
const std::string INVALID_PEP_PROTOBUF_JSON_05 = R"({"base":{"msg":"pepe has a good day","donationAddress":"P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdAFJ5pix6ppbkUC1WsDTddJVDoMf7L59CqU3yCeGoE9VnkmQHVM41YedJed96"}})";
const std::string INVALID_PEP_PROTOBUF_JSON_06 = R"({"base":{"msg":"pepe has a good day","donationAddress":"P5cyrZT9T6CUwUXA46ykaQSy1SDmmWkGgAYkdA"}})";
//invalid sig cases
const std::string INVALID_PEP_PROTOBUF_JSON_07 = R"({"base":{"msg":"pepe has a good day","pk":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="},"sig":""})";
const std::string INVALID_PEP_PROTOBUF_JSON_08 = R"({"base":{"msg":"pepe has a good day","pk":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="},"sig":"aaLyOYefih39z4VCpd7600aUn8ThimC5g/lcI5C0awuGcwkfqLHh9/0e55DVzEsn+Ml+89f10wDJbrMUiLr9BQ=="})";
const std::string INVALID_PEP_PROTOBUF_JSON_09 = R"({"base":{"msg":"pepe has a good day","pk":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="},"sig":"z4VCpd7600aUn8ThimC5g/lcI5C0awuGcwkfqLHh9/0e55DVzEsn+Ml+89f10wDJbrMUiLr9BQ=="})";
const std::string INVALID_PEP_PROTOBUF_JSON_10 = R"({"base":{"msg":"pepe has a good day day day","pk":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="},"sig":"E4LyOYefih39z4VCpd7600aUn8ThimC5g/lcI5C0awuGcwkfqLHh9/0e55DVzEsn+Ml+89f10wDJbrMUiLr9BQ=="})";
const std::string INVALID_PEP_PROTOBUF_JSON_11 = R"({"base":{"msg":"","pk":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="},"sig":"E4LyOYefih39z4VCpd7600aUn8ThimC5g/lcI5C0awuGcwkfqLHh9/0e55DVzEsn+Ml+89f10wDJbrMUiLr9BQ=="})";
//invalid fields ok sig - verification fail
const std::string INVALID_PEP_PROTOBUF_JSON_12 = R"({"base":{"msg":"blabla","pk":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="},"sig":"E4LyOYefih39z4VCpd7600aUn8ThimC5g/lcI5C0awuGcwkfqLHh9/0e55DVzEsn+Ml+89f10wDJbrMUiLr9BQ=="})";
//pk ok no sig
const std::string INVALID_PEP_PROTOBUF_JSON_13 = R"({"base":{"msg":"pepe has a good day","pk":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="}})";
//bad pk ok sig
const std::string INVALID_PEP_PROTOBUF_JSON_14 = R"({"base":{"msg":"pepe has a good day","pk":"aTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="},"sig":"E4LyOYefih39z4VCpd7600aUn8ThimC5g/lcI5C0awuGcwkfqLHh9/0e55DVzEsn+Ml+89f10wDJbrMUiLr9BQ=="})";
//bad pk no sig
const std::string INVALID_PEP_PROTOBUF_JSON_15 = R"({"base":{"msg":"pepe has a good day","pk":"aTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="}})";
//invalid tx ref
const std::string INVALID_PEP_PROTOBUF_JSON_16 = R"({"base":{"msg":"pepe has a good day","pseudonym":"pepe1","txRef":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="}})";
const std::string INVALID_PEP_PROTOBUF_JSON_17 = R"({"base":{"msg":"pepe has a good day","pseudonym":"pepe1","txRef":"FTdWOrfMY1pUK5WNTNFvLzSJZ6ePLnL/W6qHjtv5xDw="}})";

#define INVALID_PEP_PROTOBUFS_JSON \
INVALID_PEP_PROTOBUF_JSON_01,\
INVALID_PEP_PROTOBUF_JSON_02,\
INVALID_PEP_PROTOBUF_JSON_03,\
INVALID_PEP_PROTOBUF_JSON_04,\
INVALID_PEP_PROTOBUF_JSON_05,\
INVALID_PEP_PROTOBUF_JSON_06,\
INVALID_PEP_PROTOBUF_JSON_07,\
INVALID_PEP_PROTOBUF_JSON_08,\
INVALID_PEP_PROTOBUF_JSON_09,\
INVALID_PEP_PROTOBUF_JSON_10,\
INVALID_PEP_PROTOBUF_JSON_11,\
INVALID_PEP_PROTOBUF_JSON_12,\
INVALID_PEP_PROTOBUF_JSON_13,\
INVALID_PEP_PROTOBUF_JSON_14,\
INVALID_PEP_PROTOBUF_JSON_15,\
INVALID_PEP_PROTOBUF_JSON_16,\
INVALID_PEP_PROTOBUF_JSON_17\

