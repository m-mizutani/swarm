/*-
 * Copyright (c) 2013-2014 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <pcap.h>
#include <swarm.hpp>
#include "./optparse.h"

class GenHandler : public swarm::Handler {
 private:
  std::string key_;

 public:
  void set_key(const std::string &key) {
    this->key_ = key;
  }
  void recv (swarm::ev_id eid, const swarm::Property &p) {
    if (!this->key_.empty() && !p.value(this->key_).is_null()) {
      for (size_t i = 0; i < p.value_size(this->key_); i++) {
        std::cout << p.value(this->key_, i).repr() ;
        if (i + 1 < p.value_size(this->key_)) {
          std::cout << ", ";
        }
      }
      std::cout << std::endl;
    }
  }
};

bool do_benchmark (const optparse::Values& opt) {
  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec ();

  // ----------------------------------------------
  // processing packets from pcap file
  swarm::NetCap *nc = NULL;

  if (!(opt.is_set ("read_file") ^ opt.is_set ("interface"))) {
  }

  if (opt.is_set ("read_file")) {
    nc = new swarm::CapPcapFile (opt["read_file"]);
  } else if (opt.is_set("interface")) {
    nc = new swarm::CapPcapDev (opt["interface"]);
  } else {
    fprintf (stderr, "error: need specify one input method from -r, -i");
    return false;
  }

  if (nc->status () != swarm::NetCap::READY) {
    fprintf (stderr, "add device/file error: %s\n", nc->errmsg ().c_str ());
    return false;
  }

  GenHandler *gh = new GenHandler();
  assert(swarm::HDLR_NULL != nd->set_handler("ether.packet", gh));
  nc->bind_netdec (nd);

  if (opt.is_set("value")) {
    gh->set_key(opt["value"]);
  }

  if (!nc->start ()) {
    fprintf (stderr, "error: %s\n", nc->errmsg ().c_str ());
  }

  return true;
}

int main (int argc, char *argv[]) {
  optparse::OptionParser psr = optparse::OptionParser();

  psr.add_option("-i").dest("interface")
    .help("Specify read interface");
  psr.add_option("-r").dest("read_file")
    .help("Specify read pcap format file(s)");
  psr.add_option("-e").dest("event")
    .help("Event of NetCap");
  psr.add_option("-v").dest("value")
    .help("Value name of property");

  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector <std::string> args = psr.args();

  do_benchmark (opt);

  return 0;
}
