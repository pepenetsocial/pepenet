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
#include "session.h"
#include "shared_server_data.h"
// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
  net::io_context& ioc_;
  tcp::acceptor acceptor_;

  std::shared_ptr<std::mutex> sessions_mtx_;
  sessions_data sessions_data_;
  std::shared_ptr<inactive_sessions_data> inactive_sessions_data_;
  std::atomic_size_t session_id_counter_;
  std::shared_ptr<shared_server_data> shared_server_data_;

public:
  listener(
    net::io_context& ioc,
    tcp::endpoint endpoint,
    std::shared_ptr<shared_server_data> shared_server_data);

  // Start accepting incoming connections
  void run();
  // Close active sessions and stop accepting new connections
  void stop();
  // Get the number of active sessions
  std::size_t active_sessions();
  // Get the number of all started sessions
  std::size_t total_sessions();

private:
  void do_accept();

  void on_accept(beast::error_code ec, tcp::socket socket);
};

typedef std::shared_ptr<listener> listener_ptr;