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

#include "../src/proto/tcp_ssn.cc"

namespace tcp_ssn_test {
  std::string key = "aa";

  static const u_int8_t FIN  = 0x01;
  static const u_int8_t SYN  = 0x02;
  // static const u_int8_t RST  = 0x04;
  // static const u_int8_t PUSH = 0x08;
  static const u_int8_t ACK  = 0x10;
  // static const u_int8_t URG  = 0x20;
  // static const u_int8_t ECE  = 0x40;
  // static const u_int8_t CWR  = 0x80;

  TEST (TcpSession, basic) {
    swarm::TcpSession *ssn = new swarm::TcpSession(key.data(), key.length(), 1);
    
    EXPECT_TRUE(ssn->match(key.data(), key.length()));    
  }

  TEST (TcpSession, Establish) {
    const uint32_t seqL = 1000;
    const uint32_t seqR = 2000;
    
    swarm::TcpSession *ssn = new swarm::TcpSession(key.data(), key.length(), 1);


    // Establish connection
    EXPECT_EQ(swarm::CLOSED, ssn->client_stat());
    EXPECT_EQ(swarm::CLOSED, ssn->server_stat());

    // Send SYN Packet (client -> server, L2R)
    EXPECT_TRUE(ssn->update(SYN, seqL, 0, 0, swarm::DIR_L2R));
    EXPECT_EQ(swarm::SYN_SENT, ssn->client_stat());
    EXPECT_EQ(swarm::LISTEN,   ssn->server_stat());

    // Send SYN-ACK Packet (server -> client, R2L)
    EXPECT_TRUE(ssn->update(SYN | ACK, seqR, seqL + 1, 0, swarm::DIR_R2L));
    EXPECT_EQ(swarm::SYN_SENT, ssn->client_stat());
    EXPECT_EQ(swarm::SYN_RCVD, ssn->server_stat());

    // Send ACK Packet (client -> server, L2R)
    EXPECT_TRUE(ssn->update(ACK, seqL + 1, seqR + 1, 0, swarm::DIR_L2R));
    EXPECT_EQ(swarm::ESTABLISHED, ssn->client_stat());
    EXPECT_EQ(swarm::SYN_RCVD, ssn->server_stat());

    // Send data (server -> client, R2L)
    EXPECT_TRUE(ssn->update(0, seqR + 1, seqL + 1, 10, swarm::DIR_R2L));
    EXPECT_EQ(swarm::ESTABLISHED, ssn->client_stat());
    EXPECT_EQ(swarm::ESTABLISHED, ssn->server_stat());

    // Send data (client -> server, L2R)
    EXPECT_TRUE(ssn->update(0, seqL + 1, seqR + 11, 20, swarm::DIR_L2R));
    EXPECT_EQ(swarm::ESTABLISHED, ssn->client_stat());
    EXPECT_EQ(swarm::ESTABLISHED, ssn->server_stat());

    EXPECT_TRUE(ssn->update(ACK, seqR + 11, seqL + 21, 0, swarm::DIR_R2L));
    EXPECT_EQ(swarm::ESTABLISHED, ssn->client_stat());
    EXPECT_EQ(swarm::ESTABLISHED, ssn->server_stat());

    // Send fin (client -> server, L2R)
    EXPECT_TRUE(ssn->update(FIN, seqL + 21, seqR + 11, 20, swarm::DIR_L2R));
    EXPECT_EQ(swarm::CLOSING,  ssn->client_stat());
    EXPECT_EQ(swarm::ESTABLISHED, ssn->server_stat());

    // Send finack (server -> client, R2L)
    EXPECT_TRUE(ssn->update(ACK, seqR + 11, seqL + 21, 0, swarm::DIR_R2L));
    EXPECT_EQ(swarm::CLOSING, ssn->client_stat());
    EXPECT_EQ(swarm::ESTABLISHED,    ssn->server_stat());

  }
}
