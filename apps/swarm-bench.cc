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
#include <swarm.hpp>
#include "./optparse.h"

class NetDecBench : public swarm::Task {
 private:
  swarm::NetDec *nd_;
  uint64_t prev_len_;
  uint64_t prev_pkt_;
  double prev_ts_;

 public:
  explicit NetDecBench (swarm::NetDec *nd) : nd_(nd), prev_len_(0),
                                             prev_pkt_(0), prev_ts_(0) {
  }
  ~NetDecBench () {
  }
  void exec (const struct timespec &ts) {
    this->stat ();
  }
  static inline double now () {
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return static_cast<double>(tv.tv_sec) +
      static_cast<double>(tv.tv_usec) / 1000000;
  }
  void start () {
    this->prev_ts_ = NetDecBench::now ();
  }
  void stat () {
    double now_ts = NetDecBench::now ();
    double delta = now_ts - this->prev_ts_;

    uint64_t curr_len = this->nd_->recv_len ();
    uint64_t curr_pkt = this->nd_->recv_pkt ();

    double delta_len = static_cast<double>(curr_len - this->prev_len_);
    double delta_pkt = static_cast<double>(curr_pkt - this->prev_pkt_);
    printf ("%16.6f %7.3f Mbps, %7.3f Kpps\n", delta,
            (delta_len * 8) / (delta * 1000 * 1000),
            delta_pkt / (delta * 1000));

    this->prev_ts_ = now_ts;
    this->prev_len_ = curr_len;
    this->prev_pkt_ = curr_pkt;
  }
};

bool do_benchmark (const optparse::Values& opt) {
  // ----------------------------------------------
  // setup NetDec
  swarm::NetDec *nd = new swarm::NetDec ();
  NetDecBench *nd_bench = new NetDecBench (nd);

  // ----------------------------------------------
  // processing packets from pcap file
  swarm::NetCap *nc = NULL;

  if (opt.is_set ("read_file")) {
    nc = new swarm::CapPcapFile (opt["read_file"]);
  } else if (opt.is_set ("interface")) {
    nc = new swarm::CapPcapDev (opt["interface"]);
    nc->set_periodic_task (nd_bench, 1.);
  } else if (opt.is_set ("pcap_mmap")) {
    nc = new swarm::CapPcapMmap (opt["pcap_mmap"]);
  } else {
    fprintf (stderr, "error: need specify one input method from -r, -i or -f");
    return false;
  }

  if (nc->status () != swarm::NetCap::READY) {
    fprintf (stderr, "add device/file error: %s\n", nc->errmsg ().c_str ());
    return false;
  }

  nc->bind_netdec (nd);
  nd_bench->start ();
  if (!nc->start ()) {
    fprintf (stderr, "error: %s\n", nc->errmsg ().c_str ());
  }

  nd_bench->stat ();
  return true;
}

int main (int argc, char *argv[]) {
  optparse::OptionParser psr = optparse::OptionParser();

  psr.add_option("-r").dest("read_file")
    .help("Specify read pcap format file(s)");
  psr.add_option("-m").dest("pcap_mmap")
    .help("Specify read pcap format file(s) by mmap based reader");
  psr.add_option("-i").dest("interface")
    .help("Specify interface to monitor on the fly");

  optparse::Values& opt = psr.parse_args(argc, argv);
  std::vector <std::string> args = psr.args();

  do_benchmark (opt);

  return 0;
}
