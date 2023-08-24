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

#include "session.h"


  session::session(
    tcp::socket&& socket,
    std::shared_ptr<shared_server_data> shared_server_data,
    std::shared_ptr<inactive_sessions_data> inactive_sessions,
    std::size_t sessions_id)
    : stream_(std::move(socket))
    , shared_server_data_(shared_server_data)
    , lambda_(*this)
    , inactive_sessions_(inactive_sessions)
    , sessions_id_(sessions_id)
  {
  }

  // Start the asynchronous operation
  void session::run()
  {
    // We need to be executing within a strand to perform async operations
    // on the I/O objects in this session. Although not strictly necessary
    // for single-threaded contexts, this example code is written to be
    // thread-safe by default.
    net::dispatch(stream_.get_executor(),
      beast::bind_front_handler(
        &session::do_read,
        shared_from_this()));
  }

  void session::do_read()
  {
    // Make the request empty before reading,
    // otherwise the operation behavior is undefined.
    req_ = {};

    // Set the timeout.
    stream_.expires_after(std::chrono::seconds(30));

    // Read a request
    http::async_read(stream_, buffer_, req_,
      beast::bind_front_handler(
        &session::on_read,
        shared_from_this()));
  }

  void session::on_read(
      beast::error_code ec,
      std::size_t bytes_transferred)
  {
    boost::ignore_unused(bytes_transferred);
    // Add read bytes to download
    shared_server_data_->stats.download_in_bytes += bytes_transferred;
    shared_server_data_->update_server_stats_page();
    // This means they closed the connection
    if (ec == http::error::end_of_stream)
      return do_close();

    if (ec)
      return fail(ec, "read");

    // Send the response
    handle_request(shared_server_data_->filesystem.doc_root, std::move(req_), lambda_);
  }

  void session::on_write(
      bool close,
      beast::error_code ec,
      std::size_t bytes_transferred)
  {
    boost::ignore_unused(bytes_transferred);
    // Add written bytes to download
    shared_server_data_->stats.upload_in_bytes += bytes_transferred;
    shared_server_data_->update_server_stats_page();
    if (ec)
      return fail(ec, "write");

    if (close)
    {
      // This means we should close the connection, usually because
      // the response indicated the "Connection: close" semantic.
      return do_close();
    }

    // We're done with the response so delete it
    res_ = nullptr;

    // Read another request
    do_read();
  }

  void session::do_close()
  {
    // Send a TCP shutdown
    beast::error_code ec;
    stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
    // At this point the connection is closed gracefully
    // Implicitly notify the listener that this session is ready for removal
    std::lock_guard<std::mutex> lock(*inactive_sessions_->sessions_mtx_ptr);
    inactive_sessions_->idx_data.push_back(sessions_id_);
  }

//------------------------------------------------------------------------------
