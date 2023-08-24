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

#include "http_server.h"

http_server::http_server(net::ip::address address, unsigned short port, std::string doc_root, const int threads, const embedded_files& files) :
  m_address(address),
  m_port(port),
  m_num_threads(std::max<int>(1, threads)),
  m_shared_data(std::make_shared<shared_server_data>())
{
  m_shared_data->filesystem.doc_root = doc_root;
  m_shared_data->filesystem.files = files;
  m_shared_data->stats.info = server_info{ m_address.to_string(), m_port, m_num_threads };
  m_shared_data->stats.active_requests = 0;
  m_shared_data->stats.total_requests = 0;
  m_shared_data->stats.upload_in_bytes = 0;
  m_shared_data->stats.download_in_bytes = 0;

  m_shared_data->stats.start_time = std::chrono::system_clock::now();
};

void http_server::run()
{
  // The io_context is required for all I/O
  net::io_context ioc{ m_num_threads };

  // Create and launch a listening port
  m_listener = std::make_shared<listener>(
    ioc,
    tcp::endpoint{ m_address, m_port },
    m_shared_data);

  m_listener->run();

  // Run the I/O service on the requested number of threads
  m_thread_vec.reserve(m_num_threads - 1);
  for (auto i = m_num_threads - 1; i > 0; --i)
    m_thread_vec.emplace_back(
      [&ioc]
      {
        ioc.run();
      });
  ioc.run();
}

void http_server::stop()
{
  m_listener->stop();
  m_thread_vec.clear();
}

std::size_t http_server::active_sessions()
{
  return m_listener->active_sessions();
}

std::size_t http_server::total_sessions()
{
  return m_listener->total_sessions();
}

