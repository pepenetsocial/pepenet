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

#include "lzma.h"

namespace io = boost::iostreams;

namespace pepenet_social {

  bool lzma_compress_msg(const std::string& msg, std::string& compressed)
  {
    try
    {
      compressed.clear();
      std::stringstream ss;
      io::filtering_ostream out;
      out.push(io::lzma_compressor());
      out.push(ss);
      
      out << msg;
      boost::iostreams::copy(ss, out);

      compressed = ss.str();
    }
    catch (const std::exception& e)
    {
      compressed.clear();
      return false;
    }
    catch (const boost::exception& e)
    {
      compressed.clear();
      return false;
    }
    return true;
  }

  bool lzma_decompress_msg(const std::string& msg, std::string& decompressed)
  {
    try
    {
      decompressed.clear();
      io::array_source arrs{ msg.data(), msg.size() };
      io::filtering_istreambuf in;
      in.push(io::lzma_decompressor{});
      in.push(arrs);
      decompressed.assign(std::istreambuf_iterator<char>{&in}, {});
    }
    catch (const std::exception& e)
    {
      decompressed.clear();
      return false;
    }
    catch (const boost::exception& e)
    {
      decompressed.clear();
      return false;
    }
    return true;
  }

}