# Copyright (c) 2023, pepenet
# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# Http server inspired by boost::beast http server async example from https://github.com/boostorg/beast/tree/boost-1.74.0/example/http/server/async
#
# Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
#
# Distributed under the Boost Software License, Version 1.0. (See license at http://www.boost.org/LICENSE_1_0.txt)
#
# Official repository: https://github.com/boostorg/beast
#

cmake_minimum_required(VERSION 3.5)

project(http_server CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

monero_enable_coverage()

monero_find_all_headers(HTTP_SERVER_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}")
pepenet_find_all_sources(HTTP_SERVER_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}")

find_package(Boost COMPONENTS system thread REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

pepenet_add_library(http_server
  ${HTTP_SERVER_SOURCES} 
  ${HTTP_SERVER_HEADERS} 
  ${BOOST_BEAST_FILES}
)

target_link_libraries(http_server PUBLIC boost_system boost_thread)
