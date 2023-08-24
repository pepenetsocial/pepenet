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

// Report a failure
void fail(beast::error_code ec, char const* what);

// Return a reasonable mime type based on the extension of a file.
static beast::string_view
mime_type(beast::string_view path)
{
  using beast::iequals;
  auto const ext = [&path]
    {
      auto const pos = path.rfind(".");
      if (pos == beast::string_view::npos)
        return beast::string_view{};
      return path.substr(pos);
    }();
    if (iequals(ext, ".htm"))  return "text/html";
    if (iequals(ext, ".html")) return "text/html";
    if (iequals(ext, ".php"))  return "text/html";
    if (iequals(ext, ".css"))  return "text/css";
    if (iequals(ext, ".txt"))  return "text/plain";
    if (iequals(ext, ".js"))   return "application/javascript";
    if (iequals(ext, ".json")) return "application/json";
    if (iequals(ext, ".xml"))  return "application/xml";
    if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
    if (iequals(ext, ".flv"))  return "video/x-flv";
    if (iequals(ext, ".png"))  return "image/png";
    if (iequals(ext, ".jpe"))  return "image/jpeg";
    if (iequals(ext, ".jpeg")) return "image/jpeg";
    if (iequals(ext, ".jpg"))  return "image/jpeg";
    if (iequals(ext, ".gif"))  return "image/gif";
    if (iequals(ext, ".bmp"))  return "image/bmp";
    if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
    if (iequals(ext, ".tiff")) return "image/tiff";
    if (iequals(ext, ".tif"))  return "image/tiff";
    if (iequals(ext, ".svg"))  return "image/svg+xml";
    if (iequals(ext, ".svgz")) return "image/svg+xml";
    return "application/text";
}

// Append an HTTP rel-path to a local filesystem path.
// The returned path is normalized for the platform.
static std::string
path_cat(
  beast::string_view base,
  beast::string_view path)
{
  if (base.empty())
    return std::string(path);
  std::string result(base);
#ifdef BOOST_MSVC
  char constexpr path_separator = '\\';
  if (result.back() == path_separator)
    result.resize(result.size() - 1);
  result.append(path.data(), path.size());
  for (auto& c : result)
    if (c == '/')
      c = path_separator;
#else
  char constexpr path_separator = '/';
  if (result.back() == path_separator)
    result.resize(result.size() - 1);
  result.append(path.data(), path.size());
#endif
  return result;
}

template<class Body, class Allocator>
http::response<http::string_body> make_string_body_response(http::request<Body, http::basic_fields<Allocator>>&& req, const beast::string_view& data, const beast::string_view& mime_type, http::status status)
{
  http::response<http::string_body> res{status, req.version() };
  res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
  res.set(http::field::content_type, mime_type);
  res.keep_alive(false);
  res.body() = std::string(data);
  res.prepare_payload();
  return res;
}

template<class Body, class Allocator>
http::response<http::string_body> bad_request(http::request<Body, http::basic_fields<Allocator>>&& req, const beast::string_view& why)
{
  return make_string_body_response(std::move(req), why, HTML_MIME_TYPE, http::status::bad_request);
}

template<class Body, class Allocator>
http::response<http::string_body> not_found(http::request<Body, http::basic_fields<Allocator>>&& req, const beast::string_view& target)
{
  std::string response = "The resource '" + std::string(target) + "' was not found.";
  return make_string_body_response(std::move(req), response, HTML_MIME_TYPE, http::status::bad_request);
}

template<class Body, class Allocator>
http::response<http::string_body> server_error(http::request<Body, http::basic_fields<Allocator>>&& req, const beast::string_view& what)
{
  std::string response = "An error occurred: '" + std::string(what) + "'";
  return make_string_body_response(std::move(req), response, HTML_MIME_TYPE, http::status::bad_request);
}