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

// Http server inspired by boost::beast http server async example from https://github.com/boostorg/beast/tree/boost-1.74.0/example/http/server/async
//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See license at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#pragma once

#include "includes.h"
#include <boost/format.hpp>
#include <chrono>
#include <sstream>
#include <iomanip>

struct server_filesystem
{
  std::string doc_root;
  embedded_files files;
  std::mutex embedded_files_mtx;
};

struct server_info
{
  std::string ip;
  unsigned short port;
  int num_threads;
};

struct server_stats
{
  server_info info;
  std::atomic_size_t total_requests;
  std::atomic_size_t active_requests;
  std::atomic_size_t upload_in_bytes;
  std::atomic_size_t download_in_bytes;
  std::chrono::system_clock::time_point start_time;
};

struct shared_server_data
{
  server_filesystem filesystem;
  server_stats stats;
  void update_server_stats_page();
};

const std::string server_stats_page_template = R"(<!DOCTYPE html>
<html>
<body>

<h1>pepenet server stats</h1>

<h2>server info</h2>
<p>timestamp(UTC): %s</p>
<p>timestamp(unix): %i</p>
<p>ip: %s</p>
<p>port: %i</p>
<p>threads: %i</p>

<h2>server stats</h2>
<p>total requests: %i</p>
<p>active requests: %i</p>
<p>upload(kB): %f</p>
<p>download(kB): %f</p>
<p>uptime(days): %f</p>

</body>
</html>)";

std::string UTC_time_to_string(const std::chrono::system_clock::time_point& tp);
std::size_t UTC_time_to_seconds(const std::chrono::system_clock::time_point& tp);