/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
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

#include <pcap.h>
#include "../src/swarm.h"
#include "./optparse.h"

class CommonHandler : swarm::Handler {

public:
  CommonHandler() {};
  ~CommonHandler() {};
  void recv (swarm::ev_id eid, const swarm::Property &p) {
    std::cout << "pkt: " << p.src_addr() << std::endl;
  }

};


int main (int argc, char *argv[]) {
  optparse::OptionParser psr = optparse::OptionParser();

  psr.add_option("-r").dest("read_file")
    .help("Specify read pcap format file(s)");
  psr.add_option("-m").dest("pcap_mmap")
    .help("Specify read pcap format file(s) by mmap based reader");
  psr.add_option("-i").dest("interface")
    .help("Specify interface to monitor on the fly");

  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector<std::string> args = psr.args();

  swarm::Swarm *sw = NULL;
  if (opt.is_set("read_file")) { sw = new swarm::SwarmFile(opt["read_file"]); }
  if (opt.is_set("interface")) { sw = new swarm::SwarmDev(opt["interface"]);  }
  if (!sw) {
    std::cerr << "Need to specify pcap file (-r) or interface (-i)" << std::endl;
    return EXIT_FAILURE;
  }
  if (!sw->ready()) {
    std::cerr << "Not ready" << std::endl;
    return EXIT_FAILURE;
  }

  sw->start();

  return EXIT_SUCCESS;
}
