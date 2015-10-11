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


#include "./gtest.h"
#include <string>
#include "../src/swarm.hpp"

TEST(NetCap, device_name) {
  std::vector<std::string> name_list;
  std::string errmsg;
  bool rc = swarm::CapPcapDev::retrieve_device_list(&name_list, &errmsg);
  EXPECT_TRUE(rc);
  // for(size_t i = 0; i < name_list.size(); i++) {
  // printf("%s\n", name_list[i].c_str());
  // }
  EXPECT_LT(0, name_list.size());
  EXPECT_TRUE(errmsg.empty());
}

TEST(CapPcapMmap, Basic) {
  class Counter  : public swarm::Handler {
  protected:
    int c_;
  public:
    Counter () : c_(0) {}
    int count () const { return this->c_; }
    void recv (swarm::ev_id eid, const swarm::Property &prop) { this->c_++; }
  };

  swarm::NetDec *nd = new swarm::NetDec ();
  std::string sample_file = "./data/SkypeIRC.cap";
  swarm::CapPcapFile *cap = new swarm::CapPcapFile(sample_file);
  Counter *eth_count = new Counter();
  Counter *ip4_count = new Counter();
  nd->set_handler("ether.packet", eth_count);
  nd->set_handler("ipv4.packet",  ip4_count);
  cap->bind_netdec(nd);

  EXPECT_EQ(swarm::NetCap::READY, cap->status());
  EXPECT_TRUE(cap->start());
  EXPECT_EQ(2263, eth_count->count());
  EXPECT_EQ(2247, ip4_count->count());
  delete cap;
}
