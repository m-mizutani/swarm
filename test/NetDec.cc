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
#include <pcap.h>

#include "../src/swarm.hpp"

class Counter  : public swarm::Handler {
 protected:
  int count_;
 public:
  Counter () : count_(0) {}
  int count () const {
    return this->count_;
  }
};

class TestHandler : public Counter {
 public:
  void recv (swarm::ev_id eid, const swarm::Property &prop) {
    this->count_++;
  }
};

class EtherHandler : public Counter {
 private:
  swarm::val_id src_;

 public:
  explicit EtherHandler (swarm::NetDec * nd) {
    this->src_ = nd->lookup_value_id ("ether.src");
    EXPECT_NE (swarm::VALUE_NULL, this->src_);
  }
  void recv (swarm::ev_id eid, const swarm::Property &prop) {
    this->count_++;
    const swarm::Value &p = prop.value (this->src_);
    EXPECT_TRUE(!p.is_null());
  }
};

class IPv4Handler : public Counter {
 private:
  swarm::val_id src_;

 public:
  explicit IPv4Handler (swarm::NetDec * nd) {
    this->src_ = nd->lookup_value_id ("ipv4.src");
    EXPECT_NE (swarm::VALUE_NULL, this->src_);
  }
  void recv (swarm::ev_id eid, const swarm::Property &prop) {
    this->count_++;
    EXPECT_FALSE(prop.value (this->src_).is_null());
  }
};

class DnsHandler : public Counter {
 private:
  swarm::val_id type_;

 public:
  explicit DnsHandler (swarm::NetDec * nd) {
    this->type_ = nd->lookup_value_id ("dns.tx_id");
    EXPECT_NE (swarm::VALUE_NULL, this->type_);
  }
  void recv (swarm::ev_id eid, const swarm::Property &prop) {
    this->count_++;
    EXPECT_FALSE(prop.value (this->type_).is_null());
  }
};


TEST (NetDec, param) {
  swarm::NetDec *nd = new swarm::NetDec ();
  size_t base_size = nd->value_size ();
  EXPECT_EQ (0 + base_size, nd->value_size ());
  swarm::val_id p_blue   = nd->assign_value ("blue", "Blue");
  EXPECT_EQ (1 + base_size, nd->value_size ());
  swarm::val_id p_orange = nd->assign_value ("orange", "Orange");
  EXPECT_EQ (2 + base_size, nd->value_size ());

  EXPECT_NE (swarm::VALUE_NULL, p_blue);
  EXPECT_NE (swarm::VALUE_NULL, p_orange);
  EXPECT_NE (p_blue, p_orange);

  EXPECT_EQ (p_blue,   nd->lookup_value_id ("blue"));
  EXPECT_EQ (p_orange, nd->lookup_value_id ("orange"));
  EXPECT_EQ (swarm::EV_NULL, nd->lookup_value_id ("red"));

  EXPECT_EQ ("blue",   nd->lookup_value_name (p_blue));
  EXPECT_EQ ("orange", nd->lookup_value_name (p_orange));
  delete nd;
}

TEST (NetDec, event) {
  swarm::NetDec *nd = new swarm::NetDec ();
  size_t base_size = nd->event_size ();
  EXPECT_EQ (0 + base_size, nd->event_size ());
  swarm::ev_id p_blue   = nd->assign_event ("blue", "B");
  EXPECT_EQ (1 + base_size, nd->event_size ());
  swarm::ev_id p_orange = nd->assign_event ("orange", "O");
  EXPECT_EQ (2 + base_size, nd->event_size ());

  EXPECT_NE (swarm::EV_NULL, p_blue);
  EXPECT_NE (swarm::EV_NULL, p_orange);
  EXPECT_NE (p_blue, p_orange);

  EXPECT_EQ (p_blue,   nd->lookup_event_id ("blue"));
  EXPECT_EQ (p_orange, nd->lookup_event_id ("orange"));
  EXPECT_EQ (swarm::EV_NULL, nd->lookup_event_id ("red"));

  EXPECT_EQ ("blue",   nd->lookup_event_name (p_blue));
  EXPECT_EQ ("orange", nd->lookup_event_name (p_orange));
  delete nd;
}

TEST (NetDec, handler) {
  swarm::NetDec *nd = new swarm::NetDec ();
  TestHandler * th1 = new TestHandler ();
  TestHandler * th2 = new TestHandler ();

  const std::string ev1_name ("blue");
  const std::string ev2_name ("orange");
  swarm::ev_id eid1 = nd->assign_event (ev1_name, "E1");
  swarm::ev_id eid2 = nd->assign_event (ev2_name, "E2");

  swarm::hdlr_id t1 = nd->set_handler (eid1, th1);
  swarm::hdlr_id t2 = nd->set_handler (eid2, th2);

  EXPECT_NE (swarm::HDLR_NULL, t1);
  EXPECT_NE (swarm::HDLR_NULL, t2);
  EXPECT_NE (t1, t2);

  EXPECT_TRUE (th1  == nd->unset_handler (t1));
  EXPECT_TRUE (NULL == nd->unset_handler (t1));
  EXPECT_TRUE (th2  == nd->unset_handler (t2));
  EXPECT_TRUE (NULL == nd->unset_handler (t2));
}

TEST (NetDec, basic_scenario) {
  swarm::NetDec *nd = new swarm::NetDec ();
  DnsHandler * dns_h = new DnsHandler (nd);
  EtherHandler * eth_h = new EtherHandler (nd);
  IPv4Handler * ip4_h = new IPv4Handler (nd);

  swarm::ev_id eth_ev  = nd->lookup_event_id ("ether.packet");
  swarm::ev_id ip4_ev = nd->lookup_event_id ("ipv4.packet");
  swarm::ev_id dns_ev  = nd->lookup_event_id ("dns.packet");

  swarm::hdlr_id eth_hdlr = nd->set_handler (eth_ev, eth_h);
  swarm::hdlr_id ip4_hdlr = nd->set_handler (ip4_ev, ip4_h);
  swarm::hdlr_id dns_hdlr = nd->set_handler (dns_ev, dns_h);

  EXPECT_NE (swarm::EV_NULL, eth_ev);
  EXPECT_NE (swarm::EV_NULL, ip4_ev);
  EXPECT_NE (swarm::EV_NULL, dns_ev);

  EXPECT_NE (swarm::HDLR_NULL, eth_hdlr);
  EXPECT_NE (swarm::HDLR_NULL, ip4_hdlr);
  EXPECT_NE (swarm::HDLR_NULL, dns_hdlr);

  pcap_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE];
  std::string sample_file = "./data/SkypeIRC.cap";
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  pd = pcap_open_offline(sample_file.c_str (), errbuf);
  ASSERT_TRUE (pd != NULL);

  ASSERT_TRUE (DLT_EN10MB == pcap_datalink (pd));
  while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
    nd->input (pkt_data, pkthdr->len, pkthdr->ts, pkthdr->caplen);
  }

  EXPECT_EQ ( 707, dns_h->count ());
  EXPECT_EQ (2247, ip4_h->count ());
  EXPECT_EQ (2263, eth_h->count ());

  delete nd;
  delete eth_h;
  delete ip4_h;
  delete dns_h;
}


class IcmpDecoder : public swarm::Decoder {
private:
  struct icmp_header {
    u_int8_t type_;
    u_int8_t code_;
    u_int16_t checksum_;
  } __attribute__((packed));

  swarm::ev_id EV_ICMP_PKT_;
  swarm::val_id P_TYPE_, P_CODE_, P_PROTO_;
  swarm::dec_id D_IPV4_;

public:
  explicit IcmpDecoder (swarm::NetDec * nd) : swarm::Decoder (nd) {
    this->EV_ICMP_PKT_ = nd->assign_event ("icmp.packet", "ICMP Packet");
    this->P_TYPE_ =
      nd->assign_value ("icmp.type", "ICMP Type");
    this->P_CODE_ =
      nd->assign_value ("icmp.code", "ICMP Code");
  }
  void setup (swarm::NetDec * nd) {
    this->D_IPV4_  = nd->lookup_dec_id ("ipv4");
    this->P_PROTO_ = nd->lookup_value_id ("ipv4.proto");
    assert (this->P_PROTO_ != swarm::VALUE_NULL);
  };

  bool accept (const swarm::Property &p) {
    size_t s = p.value_size (this->P_PROTO_);
    // check protocol number of most recent IP header
    if (s > 0 && p.value (this->P_PROTO_, s - 1).ntoh<u_int32_t> () == 1) {
      return true;
    } else {
      return false;
    }
  }

  // Main decoding function.
  bool decode (swarm::Property *p) {
    auto hdr = reinterpret_cast <struct icmp_header *>
      (p->payload (sizeof (struct icmp_header)));
    if (hdr == NULL) {
      return false;
    }

    p->set (this->P_TYPE_, &(hdr->type_), sizeof (hdr->type_));
    p->set (this->P_CODE_, &(hdr->code_), sizeof (hdr->code_));
    p->push_event (this->EV_ICMP_PKT_);

    if (hdr->type_ == 3) {
      p->payload (4);  // adjust 4 byte
      this->emit (this->D_IPV4_, p);
    }

    return true;
  }
};

pcap_t* get_skypeirc_pcap() {
  pcap_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE];
  std::string sample_file = "./data/SkypeIRC.cap";
  pd = pcap_open_offline(sample_file.c_str (), errbuf);
  assert (pd != NULL);
  assert (DLT_EN10MB == pcap_datalink (pd));
  return pd;
}

TEST (NetDec, external_decoder_load) {
  swarm::NetDec *nd = new swarm::NetDec ();
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  pcap_t *pd = get_skypeirc_pcap ();

  swarm::dec_id d_id = nd->load_decoder ("my-icmp", new IcmpDecoder (nd));
  ASSERT_TRUE (d_id != swarm::DEC_NULL);
  ASSERT_TRUE (nd->bind_decoder (d_id, "ipv4"));

  TestHandler *th = new TestHandler ();
  nd->set_handler ("icmp.packet", th);

  while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
    nd->input (pkt_data, pkthdr->len, pkthdr->ts, pkthdr->caplen);
  }

  EXPECT_EQ (23, th->count ());
}

TEST (NetDec, external_decoder_unbind) {
  swarm::NetDec *nd = new swarm::NetDec ();
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  pcap_t *pd = get_skypeirc_pcap ();

  swarm::dec_id d_id = nd->load_decoder ("my-icmp", new IcmpDecoder (nd));
  ASSERT_TRUE (d_id != swarm::DEC_NULL);
  ASSERT_TRUE (nd->bind_decoder (d_id, "ipv4"));

  TestHandler *th = new TestHandler ();
  nd->set_handler ("icmp.packet", th);

  ASSERT_TRUE (nd->unbind_decoder (d_id, "ipv4"));

  while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
    nd->input (pkt_data, pkthdr->len, pkthdr->ts, pkthdr->caplen);
  }

  EXPECT_EQ (0, th->count ());
}

TEST (NetDec, external_decoder_unload) {
  swarm::NetDec *nd = new swarm::NetDec ();
  struct pcap_pkthdr *pkthdr;
  const u_char *pkt_data;
  pcap_t *pd = get_skypeirc_pcap ();

  swarm::dec_id d_id = nd->load_decoder ("my-icmp", new IcmpDecoder (nd));
  ASSERT_TRUE (d_id != swarm::DEC_NULL);
  ASSERT_TRUE (nd->bind_decoder (d_id, "ipv4"));

  TestHandler *th = new TestHandler ();
  nd->set_handler ("icmp.packet", th);

  ASSERT_TRUE (nd->unload_decoder (d_id));

  while (0 < pcap_next_ex (pd, &pkthdr, &pkt_data)) {
    nd->input (pkt_data, pkthdr->len, pkthdr->ts, pkthdr->caplen);
  }

  EXPECT_EQ (0, th->count ());
}
