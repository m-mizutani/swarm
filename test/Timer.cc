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

#include <time.h>
#include <pcap.h>
#include <string.h>

#include "./gtest.h"
#include "../src/debug.hpp"
#include "../src/swarm.hpp"

TEST(Timer, set_unset) {
  class Worker : public swarm::Task {
  public:
    int i_;
    Worker() : i_(0) {}
    void exec(const struct timespec &ts) {
      this->i_++;
    }
  };

  Worker *w = new Worker();

  std::vector<std::string> name_list;
  std::string errmsg;
  swarm::CapPcapDev::retrieve_device_list(&name_list, &errmsg);
  ASSERT_LT(0, name_list.size());

  swarm::NetCap *nc = new swarm::CapPcapDev(name_list[0]);
  swarm::task_id tid1 = nc->set_periodic_task(w, 1.);
  swarm::task_id tid2 = nc->set_periodic_task(w, 1.5);
  EXPECT_NE(tid1, tid2);
  EXPECT_TRUE(nc->unset_task(tid1));
  EXPECT_FALSE(nc->unset_task(tid1));
  EXPECT_TRUE(nc->unset_task(tid2));
  EXPECT_FALSE(nc->unset_task(tid2));
}

TEST(Timer, run_timer) {
  class Worker : public swarm::Task {
  public:
    int i_;
    Worker() : i_(0) {}
    void exec(const struct timespec &ts) {
      this->i_++;
    }
  };

  std::vector<std::string> name_list;
  std::string errmsg;
  swarm::CapPcapDev::retrieve_device_list(&name_list, &errmsg);
  ASSERT_LT(0, name_list.size());

  Worker *w = new Worker();
  swarm::NetCap *nc = new swarm::CapPcapDev(name_list[0]);

  ASSERT_EQ(swarm::NetCap::READY, nc->status());
  swarm::task_id tid1 = nc->set_periodic_task(w, 0.1);
  nc->start(1.);
  // Periodic task per 0.1 second should be called 10 time in 1 second
  EXPECT_LE(5, w->i_);
  EXPECT_GT(15, w->i_);
}
