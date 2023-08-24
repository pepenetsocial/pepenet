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
#include "helpers.h"
#include "shared_server_data.h"

struct inactive_sessions_data
{
  std::vector<std::size_t> idx_data;
  std::shared_ptr<std::mutex> sessions_mtx_ptr;
};

// Handles an HTTP server connection
class session : public std::enable_shared_from_this<session>
{
  // This is the C++11 equivalent of a generic lambda.
  // The function object is used to send an HTTP message.
  struct send_lambda
  {
    session& self_;

    explicit
      send_lambda(session& self)
      : self_(self)
    {
    }

    template<bool isRequest, class Body, class Fields>
    void
      operator()(http::message<isRequest, Body, Fields>&& msg) const
    {
      // The lifetime of the message has to extend
      // for the duration of the async operation so
      // we use a shared_ptr to manage it.
      auto sp = std::make_shared<
        http::message<isRequest, Body, Fields>>(std::move(msg));

      // Store a type-erased version of the shared
      // pointer in the class to keep it alive.
      self_.res_ = sp;

      // Write the response
      http::async_write(
        self_.stream_,
        *sp,
        beast::bind_front_handler(
          &session::on_write,
          self_.shared_from_this(),
          sp->need_eof()));
    }
  };

  beast::tcp_stream stream_;
  beast::flat_buffer buffer_;
  http::request<http::string_body> req_;
  std::shared_ptr<void> res_;
  send_lambda lambda_;
  std::shared_ptr<inactive_sessions_data> inactive_sessions_;
  std::size_t sessions_id_;
  std::shared_ptr<shared_server_data> shared_server_data_;

public:
  // Take ownership of the stream
  session(
    tcp::socket&& socket,
    std::shared_ptr<shared_server_data> shared_server_data,
    std::shared_ptr<inactive_sessions_data> inactive_sessions,
    std::size_t sessions_id);

  // Start the asynchronous operation
  void run();

  void do_read();

  void on_read(
    beast::error_code ec,
    std::size_t bytes_transferred);

  void on_write(
    bool close,
    beast::error_code ec,
    std::size_t bytes_transferred);

  void do_close();
  
  template<class Body, class Allocator, class Send>
  void handle_request(
    beast::string_view doc_root,
    http::request<Body, http::basic_fields<Allocator>>&& req,
    Send&& send);
};

//------------------------------------------------------------------------------
typedef std::shared_ptr<session> session_ptr;

struct sessions_data
{
  std::unordered_map<std::size_t, session_ptr> sessions_data;
  std::shared_ptr<std::mutex> sessions_mtx_ptr;
};


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<class Body, class Allocator, class Send>
void session::handle_request(
  beast::string_view doc_root,
  http::request<Body, http::basic_fields<Allocator>>&& req,
  Send&& send)
{
  // Make sure we can handle the method
  if (req.method() != http::verb::get &&
    req.method() != http::verb::head)
    return send(bad_request(std::move(req), "Unknown HTTP-method"));

  // Request path must be absolute and not contain "..".
  if (req.target().empty() ||
    req.target()[0] != '/' ||
    req.target().find("..") != beast::string_view::npos)
    return send(bad_request(std::move(req), "Illegal request-target"));

  // Check if embedded file is requested
  std::string embedded_file_path = static_cast<std::string>(req.target());
  if (req.target().back() == '/')
    embedded_file_path.append("index.html");

  {
    std::lock_guard<std::mutex> lock(shared_server_data_->filesystem.embedded_files_mtx);
    embedded_files& files = shared_server_data_->filesystem.files;
    if (files.find(embedded_file_path) != files.end())
    {
      return send(make_string_body_response(std::move(req), files.at(embedded_file_path), mime_type(embedded_file_path), http::status::ok));
    }
  }

  // Build the path to the requested file
  std::string path = path_cat(doc_root, req.target());
  if (req.target().back() == '/')
    path.append("index.html");

  // Attempt to open the file
  beast::error_code ec;
  http::file_body::value_type body;
  body.open(path.c_str(), beast::file_mode::scan, ec);

  // Handle the case where the file doesn't exist
  if (ec == beast::errc::no_such_file_or_directory)
    return send(not_found(std::move(req), req.target()));

  // Handle an unknown error
  if (ec)
    return send(server_error(std::move(req), ec.message()));

  // Cache the size since we need it after the move
  auto const size = body.size();

  // Respond to HEAD request
  if (req.method() == http::verb::head)
  {
    http::response<http::empty_body> res{ http::status::ok, req.version() };
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, mime_type(path));
    res.content_length(size);
    res.keep_alive(false);
    return send(std::move(res));
  }

  // Respond to GET request
  http::response<http::file_body> res{
      std::piecewise_construct,
      std::make_tuple(std::move(body)),
      std::make_tuple(http::status::ok, req.version()) };
  res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
  res.set(http::field::content_type, mime_type(path));
  res.content_length(size);
  res.keep_alive(false);
  return send(std::move(res));
}