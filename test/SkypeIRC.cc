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
#include <string.h>

#include "./gtest.h"
#include "../src/debug.hpp"
#include "../src/swarm.hpp"

namespace SkypeIRC {
  class PcapData {
  private:
    u_char *pkt_data_;
    struct timeval ts_;
    int dlt_;
    size_t len_, caplen_;

  public:
    PcapData (const u_char *pkt_data, struct pcap_pkthdr *pkthdr, int dlt) {
      this->pkt_data_ = static_cast<u_char*> (malloc (pkthdr->caplen));
      ::memcpy (this->pkt_data_, pkt_data, pkthdr->caplen);
      this->len_    = static_cast <size_t> (pkthdr->len);
      this->caplen_ = static_cast <size_t> (pkthdr->caplen);
      ::memcpy (&(this->ts_), &(pkthdr->ts), sizeof (this->ts_));
      this->dlt_ = dlt;
    }
    ~PcapData () {
      free (this->pkt_data_);
    }

    u_char * pkt_data () const { return this->pkt_data_; }
    int dlt () const { return this->dlt_; }
    struct timeval * ts () { return &(this->ts_); }
    size_t len () const { return this->len_; }
    size_t caplen () const { return this->caplen_; }
  };

  class SkypeIRCFix : public ::testing::Test {
  public:
    swarm::NetDec *nd;
    std::deque <PcapData *> test_data;

    virtual void SetUp() {
      pcap_t *pd;
      nd = new swarm::NetDec ();
      char errbuf[PCAP_ERRBUF_SIZE];
      const std::string sample_file = "./data/SkypeIRC.cap";
      struct pcap_pkthdr *pkthdr;
      const u_char *pkt_data;
      pd = pcap_open_offline(sample_file.c_str (), errbuf);
      ASSERT_TRUE (pd != NULL);

      int dlt = pcap_datalink (pd);
      while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
        PcapData *p = new PcapData (pkt_data, pkthdr, dlt);
        test_data.push_back (p);
      }
    }

    virtual void TearDown() {
      while (!test_data.empty ()) {
        PcapData * p = test_data.front ();
        delete p;
        test_data.pop_front ();
      }
    }
  };

  class Counter  : public swarm::Handler {
  private:
    int count_;

  protected:
    std::string tgt_;
    void countup () {
      this->count_++;
    }

  public:
    Counter () : count_(0) {}
    virtual void recv (swarm::ev_id eid, const swarm::Property &prop) {
      this->countup ();
    }
    int count () const {
      return this->count_;
    }
  };

  class CountTest {
  private:
    Counter * hdlr_;
    int count_;
    std::string ev_;
  public:
    CountTest (Counter * hdlr, std::string ev, int count) :
      hdlr_(hdlr), count_(count), ev_(ev) {}
    void install (swarm::NetDec *nd) {
      swarm::hdlr_id hid = nd->set_handler (this->ev_, this->hdlr_);
      ASSERT_NE (swarm::HDLR_NULL, hid);
    }
    void check () {
      EXPECT_EQ (this->count_, this->hdlr_->count ());
    }
  };



  TEST_F (SkypeIRCFix, arp) {
    class RepCount : public Counter {
    public:
      void recv (swarm::ev_id eid, const swarm::Property &prop) {
        const bool DEBUG = false;
        std::string src_pr = prop.value ("arp.src_pr").repr ();
        std::string dst_pr = prop.value ("arp.dst_pr").repr ();
        std::string src_hw = prop.value ("arp.src_hw").mac ();
        std::string dst_hw = prop.value ("arp.dst_hw").mac ();
        std::string op = prop.value ("arp.op").repr ();

        if (DEBUG) {
          debug (1, "src_pr = %s", src_pr.c_str ());
          debug (1, "src_hw = %s", src_hw.c_str ());
          debug (1, "dst_pr = %s", dst_pr.c_str ());
          debug (1, "dst_hw = %s", dst_hw.c_str ());
        }
        if (op == "REPLY" &&
            dst_pr == "192.168.1.1" && dst_hw == "00:16:E3:19:27:15" &&
            src_pr == "192.168.1.2" && src_hw == "00:04:76:96:7B:DA") {
          this->countup ();
        }
      }
    };

    class ReqCount : public Counter {
      void recv (swarm::ev_id eid, const swarm::Property &prop) {
        const bool DEBUG = false;
        std::string src_pr = prop.value ("arp.src_pr").ip4 ();
        std::string dst_pr = prop.value ("arp.dst_pr").ip4 ();
        std::string src_hw = prop.value ("arp.src_hw").mac ();
        std::string dst_hw = prop.value ("arp.dst_hw").mac ();
        std::string op = prop.value ("arp.op").repr ();

        if (DEBUG) {
          debug (1, "src_pr = %s", src_pr.c_str ());
          debug (1, "src_hw = %s", src_hw.c_str ());
          debug (1, "dst_pr = %s", dst_pr.c_str ());
          debug (1, "dst_hw = %s", dst_hw.c_str ());
        }
        if (op == "REQUEST" &&
            src_pr == "192.168.1.1" && src_hw == "00:16:E3:19:27:15" &&
            dst_pr == "192.168.1.2" && dst_hw == "00:00:00:00:00:00") {
          this->countup ();
        }
      }
    };

    Counter *h1 = new Counter ();
    Counter *h2 = new Counter ();
    Counter *h3 = new Counter ();
    Counter *req = new ReqCount ();
    Counter *rep = new RepCount ();

    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.packet",  h1));
    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.request", h2));
    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.reply",   h3));

    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.request", req));
    ASSERT_NE (swarm::HDLR_NULL, nd->set_handler ("arp.reply",   rep));

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

    EXPECT_EQ (10, h1->count ());
    EXPECT_EQ (5, h2->count ());
    EXPECT_EQ (5, h3->count ());
    EXPECT_EQ (5, req->count ());
    EXPECT_EQ (5, rep->count ());
  }

  TEST_F (SkypeIRCFix, ether) {
    Counter *h1 = new Counter ();
    swarm::hdlr_id hid = nd->set_handler ("ether.packet", h1);

    ASSERT_NE (swarm::HDLR_NULL, hid);

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

    EXPECT_EQ (2263, h1->count ());
  }



  TEST_F (SkypeIRCFix, ipv4) {
    class SrcCount : public Counter {
    public:
      explicit SrcCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.value ("ipv4.src").repr () == this->tgt_) { this->countup (); }
      }
    };

    class DstCount : public Counter {
    public:
      explicit DstCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.value ("ipv4.dst").repr () == this->tgt_) { this->countup (); }
      }
    };

    class ProtoCount : public Counter {
    public:
      explicit ProtoCount (const std::string &proto) { this->tgt_ = proto; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.value ("ipv4.proto").repr () == this->tgt_) { this->countup (); }
      }
    };

    class LenCount : public Counter {
    public:
      explicit LenCount (const std::string &tgt) { this->tgt_ = tgt; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        std::string data = p.value ("ipv4.total").repr ();
        if (data == this->tgt_) { this->countup (); }
      }
    };


    std::deque <CountTest *> tests_;
#define __REG_TC(HDLR, EV_NAME, COUNT) \
    tests_.push_back (new CountTest ((HDLR), EV_NAME, COUNT));

    __REG_TC (new Counter (), "ipv4.packet", 2247);
    __REG_TC (new SrcCount ("212.204.214.114"), "ipv4.packet", 141);
    __REG_TC (new DstCount ("71.10.179.129"), "ipv4.packet", 43);
    __REG_TC (new SrcCount ("212.204.214.114"), "ipv4.packet", 141);
    __REG_TC (new ProtoCount ("TCP"), "ipv4.packet", 1150);
    __REG_TC (new ProtoCount ("UDP"), "ipv4.packet", 1072);
    __REG_TC (new LenCount ("79"), "ipv4.packet", 28);
#undef __REG_TC

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->install (nd);
    }

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->check ();
    }
  }


  TEST_F (SkypeIRCFix, udp) {
    class SrcCount : public Counter {
    public:
      explicit SrcCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.value ("udp.src_port").repr () == this->tgt_) {
          this->countup ();
        }
      }
    };

    class DstCount : public Counter {
    public:
      explicit DstCount (const std::string &addr) { this->tgt_ = addr; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.value ("udp.dst_port").repr () == this->tgt_) {
          this->countup ();
        }
      }
    };

    class LenCount : public Counter {
    public:
      explicit LenCount (const std::string &proto) { this->tgt_ = proto; }
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.value ("udp.len").repr () == this->tgt_) {
          this->countup ();
        }
      }
    };



    std::deque <CountTest *> tests_;
#define __REG_TC(HDLR, EV_NAME, COUNT) \
    tests_.push_back (new CountTest ((HDLR), EV_NAME, COUNT));

    __REG_TC (new Counter (), "udp.packet", 1072);
    __REG_TC (new SrcCount ("53"), "udp.packet", 353);
    __REG_TC (new DstCount ("53"), "udp.packet", 354);
    __REG_TC (new LenCount ("38"), "udp.packet", 29);
#undef  __REG_TC

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->install (nd);
    }

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->check ();
    }
  }



  TEST_F (SkypeIRCFix, Stat) {
    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

    EXPECT_EQ (384637, nd->recv_len ());
    EXPECT_EQ (384637, nd->cap_len ());
    EXPECT_EQ (2263,   nd->recv_pkt ());
    EXPECT_DOUBLE_EQ (322.74977612495422, nd->last_ts () - nd->init_ts ());
  }

  TEST_F (SkypeIRCFix, tcp) {
    class HashCount : public Counter {
    public:
      std::set<uint64_t> hash_set_;
      std::set<std::string> label_set_;

      void recv (swarm::ev_id eid, const swarm::Property &p) {        
        this->hash_set_.insert(p.hash_value());
        size_t len;
        const void *ptr = p.ssn_label(&len);
        std::string buf(reinterpret_cast<const char*>(ptr), len * sizeof(char));
        this->label_set_.insert(buf);
      }
    };

    class KeyCount : public Counter {
    private:
      const std::string key_;
    public:
      explicit KeyCount (const std::string &key, const std::string &value) : 
        key_(key) { this->tgt_ = value; } 
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.value (this->key_).repr () == this->tgt_) { this->countup (); }
      }
    };
    
    std::deque <CountTest *> tests_;
#define __REG_TC(HDLR, EV_NAME, COUNT) \
    tests_.push_back (new CountTest ((HDLR), EV_NAME, COUNT));

    __REG_TC (new Counter (), "udp.packet", 1072);
    __REG_TC (new KeyCount ("tcp.src_port", "2057"), "tcp.packet", 2);
    __REG_TC (new KeyCount ("tcp.dst_port", "2057"), "tcp.packet", 3);
    __REG_TC (new KeyCount ("tcp.src_port", "6667"), "tcp.packet", 141);
    __REG_TC (new KeyCount ("tcp.dst_port", "6667"), "tcp.packet", 159);

#undef  __REG_TC

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->install (nd);
    }

    HashCount *hc = new HashCount();
    nd->set_handler("tcp.packet", hc);

    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

    for (auto it = tests_.begin (); it != tests_.end (); it++) {
      (*it)->check ();
    }

    EXPECT_EQ (98, hc->hash_set_.size());
    EXPECT_EQ (98, hc->label_set_.size());
    delete hc;
  }

  TEST_F (SkypeIRCFix, tcp_ssn) {
    class DataCount : public Counter {
    public:
      std::deque<size_t> src_size_, dst_size_;
      explicit DataCount () {}
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        size_t len;
        // if (p.value("tcp_ssn.segment").ptr(&len) != NULL) {
        if (!p.value("tcp_ssn.segment").is_null()) {
          p.value("tcp_ssn.segment").ptr(&len);
          if (p.src_addr() == "195.215.8.141") {
            this->src_size_.push_back(len);
          } else if (p.dst_addr() == "195.215.8.141") {
            this->dst_size_.push_back(len);
          }
        }
      }
    };

    DataCount *dc = new DataCount();
    nd->set_handler("tcp.packet", dc);
    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

    EXPECT_EQ(3, dc->src_size_.size());
    EXPECT_EQ(5,   dc->src_size_.at(0));
    EXPECT_EQ(232, dc->src_size_.at(1));
    EXPECT_EQ(67,  dc->src_size_.at(2));

    EXPECT_EQ(3, dc->dst_size_.size());
    EXPECT_EQ(5,   dc->dst_size_.at(0));
    EXPECT_EQ(451, dc->dst_size_.at(1));
    EXPECT_EQ(18,  dc->dst_size_.at(2));
  }


  TEST_F (SkypeIRCFix, dns) {
    class DataCount : public Counter {
    public:
      explicit DataCount () {}
      void recv (swarm::ev_id eid, const swarm::Property &p) {

        // std::cout << "---------" << std::endl;
        for (size_t i = 0; i < p.value_size("dns.an_name"); i++) {
          // std::cout << i << ": " << p.value("dns.an_name", i).repr() << std::endl;
        }
      }
    };

    DataCount *dc = new DataCount();
    nd->set_handler("dns.packet", dc);
    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }

  }

  TEST_F (SkypeIRCFix, has_port) {
    class PortCount : public Counter {
    public:
      explicit PortCount () {}
      void recv (swarm::ev_id eid, const swarm::Property &p) {
        if (p.has_port()) {
          this->countup();
        }
      }
    };

    PortCount *dc = new PortCount();
    nd->set_handler("ether.packet", dc);
    for (auto it = test_data.begin (); it != test_data.end (); it++) {
      PcapData * p = (*it);
      nd->input (p->pkt_data (), p->len (), *(p->ts ()), p->caplen ());
    }
    EXPECT_EQ(2222, dc->count());
  }
  
}  // namespace SkypeIRC
