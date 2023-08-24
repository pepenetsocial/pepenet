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

#include "shared_server_data.h"

void shared_server_data::update_server_stats_page()
{
  auto now = std::chrono::system_clock::now();
  double uptime_in_days = (UTC_time_to_seconds(now) - UTC_time_to_seconds(stats.start_time)) / 86400.0;
  std::string constructed_server_stats_page = (boost::format(server_stats_page_template)
    % UTC_time_to_string(now) //utc timestamp
    % UTC_time_to_seconds(now) //unix timestamp
    % stats.info.ip
    % stats.info.port
    % stats.info.num_threads
    % stats.total_requests
    % stats.active_requests
    % (stats.upload_in_bytes / 1024.0)
    % (stats.download_in_bytes / 1024.0)
    % uptime_in_days).str(); //uptime

  std::lock_guard<std::mutex> lock(filesystem.embedded_files_mtx);
  filesystem.files["/pepenet/server_stats.html"] = constructed_server_stats_page;
}

std::string UTC_time_to_string(const std::chrono::system_clock::time_point& tp)
{
  auto itt = std::chrono::system_clock::to_time_t(tp);
  std::ostringstream ss;
  ss << std::put_time(gmtime(&itt), "%F %T");
  return ss.str();
}

std::size_t UTC_time_to_seconds(const std::chrono::system_clock::time_point& tp)
{
  std::chrono::system_clock::duration dtn = tp.time_since_epoch();
  return std::chrono::duration_cast<std::chrono::seconds>(dtn).count();
}