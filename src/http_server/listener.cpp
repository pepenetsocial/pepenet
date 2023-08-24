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

#include "listener.h"

listener::listener(
  net::io_context& ioc,
  tcp::endpoint endpoint,
  std::shared_ptr<shared_server_data> shared_server_data)
  : ioc_(ioc)
  , acceptor_(net::make_strand(ioc))
  , shared_server_data_(shared_server_data)
  , session_id_counter_(0)
{
    //make required pointers for session management
    sessions_mtx_ = std::make_shared<std::mutex>();
    inactive_sessions_data_ = std::make_shared<inactive_sessions_data>();
    //note that they share the same mutex
    sessions_data_.sessions_mtx_ptr = sessions_mtx_;
    inactive_sessions_data_->sessions_mtx_ptr = sessions_mtx_;
    //init listener
    beast::error_code ec;

    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if (ec)
    {
      fail(ec, "open");
      return;
    }

    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec)
    {
      fail(ec, "set_option");
      return;
    }

    // Bind to the server address
    acceptor_.bind(endpoint, ec);
    if (ec)
    {
      fail(ec, "bind");
      return;
    }

    // Start listening for connections
    acceptor_.listen(
      net::socket_base::max_listen_connections, ec);
    if (ec)
    {
      fail(ec, "listen");
      return;
    }
  }

  // Start accepting incoming connections
  void listener::run()
  {
    do_accept();
  }

  void listener::stop()
  {
    // Stop accepting new connections
    acceptor_.close();
    // Close exiting sessions
    for (auto& session : sessions_data_.sessions_data)
    {
      session.second->do_close();
    }
    // Remove all sessions
    sessions_data_.sessions_data.clear();
  }

  std::size_t listener::active_sessions()
  {
    std::lock_guard<std::mutex> lock(*sessions_mtx_);
    // All sessions - known inactive sessions
    return sessions_data_.sessions_data.size() - inactive_sessions_data_->idx_data.size();
  }

  std::size_t listener::total_sessions()
  {
    return session_id_counter_;
  }

  void
    listener::do_accept()
  {
    // The new connection gets its own strand
    acceptor_.async_accept(
      net::make_strand(ioc_),
      beast::bind_front_handler(
        &listener::on_accept,
        shared_from_this()));
  }

  void
    listener::on_accept(beast::error_code ec, tcp::socket socket)
  { 
    if (ec)
    {
      fail(ec, "accept");
    }
    else
    {
      // Create the session, run it and add it to vector
      std::lock_guard<std::mutex> lock(*sessions_data_.sessions_mtx_ptr);
      // Get id of new session
      session_ptr new_session = std::make_shared<session>(
        std::move(socket),
        shared_server_data_,
        inactive_sessions_data_,
        session_id_counter_);
      new_session->run();
      sessions_data_.sessions_data[session_id_counter_++] = new_session;
      // Remove the inactive sessions
      for (const auto& idx : inactive_sessions_data_->idx_data)
      {
        sessions_data_.sessions_data.erase(idx);
      }
      inactive_sessions_data_->idx_data.clear();
    }
    // Update the stats
    shared_server_data_->stats.active_requests = active_sessions();
    shared_server_data_->stats.total_requests = total_sessions();

    // Accept another connection
    do_accept();
  }