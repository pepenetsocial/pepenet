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

//feature limits - size in bytes
#define LZMA_PEP_MAX_SIZE 512
#define LZMA_POST_MAX_SIZE 4096
#define POST_TITLE_MAX_SIZE 128
#define PSEUDONYM_MAX_SIZE 32
#define PEPETAG_MAX_SIZE 32
#define DONATION_ADDRESS_MAX_SIZE 108
#define DONATION_ADDRESS_MIN_SIZE 97

#define INFO_NULLOPT boost::optional<std::string>()

#define RETURN_IBOOL_IF(expr, b, info){if(expr){return pepenet_social::ibool{b, std::string(info)};}}
#define CHECK_AND_ASSERT_RETURN_IBOOL(expr, info) RETURN_IBOOL_IF(!(expr), false, info)
#define CHECK_AND_ASSERT_RERETURN_IBOOL(ibool) RETURN_IBOOL_IF(!(ibool.b), ibool.b, ibool.info.value_or(""))

#define FALSE_IBOOL(info) pepenet_social::ibool{false, std::string(info)}

//feature tags
#define PEP_SOCIAL_FEATURE_TAG  0x00
#define POST_SOCIAL_FEATURE_TAG 0x01