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

#include <sstream>
#include "../swarm/decode.hpp"
#include "./utils/lru_hash.hpp"
#include "../debug.hpp"

namespace swarm {
  enum TcpStat {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    CLOSING,
    TIME_WAIT,
  };

  class TcpSession : public LRUHash::Node {
    static const u_int8_t FIN  = 0x01;
    static const u_int8_t SYN  = 0x02;
    static const u_int8_t RST  = 0x04;
    static const u_int8_t PUSH = 0x08;
    static const u_int8_t ACK  = 0x10;
    static const u_int8_t URG  = 0x20;
    static const u_int8_t ECE  = 0x40;
    static const u_int8_t CWR  = 0x80;

  private:
    void *key_;
    size_t len_;
    uint64_t hash_;
    time_t ts_;

    class Node {
    private:
      uint32_t base_seq_;
      uint32_t sent_len_;
      uint32_t next_ack_;
      bool avail_seq_;
      bool avail_ack_;
      TcpStat stat_;

      bool recv_fin_;
      bool recv_finack_;
      bool sent_finack_;
      bool updated_;

    public:
      Node() : 
        base_seq_(0),
        sent_len_(0),
        next_ack_(0),
        avail_seq_(false),
        avail_ack_(false),
        stat_(CLOSED),
        recv_fin_(false),
        recv_finack_(false),
        sent_finack_(false),
        updated_(false) {
      }
      ~Node() {};
      inline TcpStat stat() const { return this->stat_; }
      bool updated() const { return this->updated_; }

      void update_stat(TcpStat stat) {
        this->stat_ = stat;
        this->updated_ = true;
      }
      bool recv(uint8_t flags, uint32_t seq, uint32_t ack, size_t data_len) {
        assert((~(SYN | ACK | FIN | RST) & flags) == 0);
        this->updated_ = false;

        switch(this->stat_) {
        case CLOSED:
          if (flags == SYN) {
            // Server recieves SYN packet
            this->update_stat(LISTEN);
            this->next_ack_ = seq + 1;
            this->avail_ack_ = true;
          }
          break;

        case LISTEN:
          break;

        case SYN_SENT:
          if (flags == (SYN|ACK)) {
            // Client recieves SYN|ACK packet
            this->next_ack_ = seq + 1;
            this->avail_ack_ = true;
          }
          break;

        case SYN_RCVD:
          break;

        case ESTABLISHED: 
          if ((flags & FIN) > 0) {
            this->recv_fin_ = true;
          }
          break;

        case CLOSING:
          if ((flags & FIN) > 0) {
            this->recv_fin_ = true;
          }
            
          if ((flags & ACK) > 0) {
            this->recv_finack_ = true;
          }
            
          if (this->recv_fin_ && this->recv_finack_ && this->sent_finack_) {
            this->update_stat(TIME_WAIT);
          }
          break;
            
        case TIME_WAIT:
          break;
        }

        if (this->stat_ == ESTABLISHED || this->stat_ == SYN_RCVD) {
          this->next_ack_ += data_len;
        }
        return true;
      }

      /*
        State Transition

        -- Client -------------- Server --
         [CLOSING]               [CLOSING]
            |       ---(SYN)--->    |
         [SYN_SENT]              [LISTEN]
            |       <-(SYN|ACK)-    |
         [SYN_SENT]              [SYN_RECV]
            |       ---(ACK)-->     |
         [ESTABLISH]             [SYN_RECV]
            |    <--(ACK or Data)-- |
         [ESTABLISH]             [ESTABLISH]
            |                       |
      */

      bool send(uint8_t flags, uint32_t seq, uint32_t ack, size_t data_len) {
        assert((~(SYN | ACK | FIN | RST) & flags) == 0);
        this->updated_ = false;

        switch(this->stat_) {
        case CLOSED:
          if (flags == SYN) {
            this->update_stat(SYN_SENT);
            this->base_seq_ = seq;
            this->avail_seq_ = true;
          }
          break;

        case LISTEN:
          // Server sends SYN|ACK packet
          if (flags == (SYN|ACK)) {
            this->update_stat(SYN_RCVD);
            this->base_seq_ = seq;
            this->avail_seq_ = true;
          }
          break;

        case SYN_SENT:
          // Client sends ACK packet after SYN|ACK
          if (flags == ACK) {
            this->update_stat(ESTABLISHED);
          }
          break;

        case SYN_RCVD: 
          if (flags == FIN) {
            this->update_stat(CLOSING);
          } else {
            this->update_stat(ESTABLISHED);
          }
          break;

        case ESTABLISHED:
          if ((flags & FIN) > 0) {
            this->update_stat(CLOSING);
          }
          if (this->recv_fin_ && (flags & ACK) > 0) {
            this->sent_finack_ = true;
          }
          break;

        case CLOSING:
          if (this->recv_fin_ && (flags & ACK) > 0) {
            this->sent_finack_ = true;
          }
          
          break;

        case TIME_WAIT:
            break; // nothing to do.
        }

        if (this->stat_ == ESTABLISHED) {
          this->sent_len_ += data_len;
        }
        return true;
      }

      bool check_seq(uint32_t seq, uint32_t ack) const {
        if ((!this->avail_seq_ || (this->base_seq_ + this->sent_len_ + 1 <= seq)) &&
            (!this->avail_ack_ || (this->next_ack_))) {
          return true;
        } else {
          return false;
        }
      }

    } server_, client_;
    FlowDir dir_;

  public:
    TcpSession(const void *key, size_t key_len, uint64_t hash)
      : dir_(DIR_NIL) {
      this->len_ = key_len;
      this->key_ = ::malloc(key_len);
      ::memcpy(this->key_, key, this->len_);
      this->hash_ = hash;

      ::memset(&this->server_, 0, sizeof(this->server_));
      ::memset(&this->client_, 0, sizeof(this->client_));
    }
    ~TcpSession() {
      if(this->key_) {
        ::free(this->key_);
      }
    }
    void set_ts(time_t ts) {
      this->ts_ = ts;
    }
    time_t ts() const {
      return this->ts_; 
    }
    bool match(const void *key, size_t len) {
      return (this->len_ == len && 0 == ::memcmp(this->key_, key, len));
    }
    uint64_t hash() {
      return this->hash_;
    }
    inline bool to_server(FlowDir dir) const {
      return (this->dir_ == dir && this->dir_ != DIR_NIL);
    }
    inline bool to_client(FlowDir dir) const {
      return (this->dir_ != dir && this->dir_ != DIR_NIL);
    }
    inline TcpStat server_stat() const {
      return this->server_.stat();
    }
    inline TcpStat client_stat() const {
      return this->client_.stat();
    }
    inline bool is_data_available(FlowDir dir) const {
      const Node *sender = (this->dir_ == dir) ? &this->client_ : &this->server_;
      if (!sender->updated() && sender->stat() == ESTABLISHED) {
        return true;
      } else {
        return false;
      }
    }

    bool update(uint8_t flags, uint32_t seq, uint32_t ack, size_t data_len,
                FlowDir dir) {
      uint8_t f = flags & (FIN | SYN | RST | ACK);
      bool rc = true;

#if 0
      const bool DBG = true;
      std::stringstream ss;
      if ((f & FIN) > 0) { ss << "F"; } else { ss << "_"; }
      if ((f & SYN) > 0) { ss << "S"; } else { ss << "_"; }
      if ((f & RST) > 0) { ss << "R"; } else { ss << "_"; }
      if ((f & PUSH) > 0) { ss << "P"; } else { ss << "_"; }
      if ((f & ACK) > 0) { ss << "A"; } else { ss << "_"; }
      if ((f & URG) > 0) { ss << "U"; } else { ss << "_"; }
      if ((f & ECE) > 0) { ss << "E"; } else { ss << "_"; }
      if ((f & CWR) > 0) { ss << "C"; } else { ss << "_"; }

      std::string s_dir = "NIL";
      if (dir == DIR_L2R) { s_dir = "L2R"; }
      else if (dir == DIR_R2L) { s_dir = "R2L"; }

      debug(DBG, "seq: %u, ack: %u, dir:%s, flag:%s, len:%zd",
            seq, ack, s_dir.c_str(), ss.str().c_str(), data_len);
#endif


      if (this->dir_ == DIR_NIL) {
        // Initialize: server and client are determined by SYN packet direction
        if (f == SYN) {
          this->dir_ = dir;
          this->client_.send(f, seq, ack, data_len);
          this->server_.recv(f, seq, ack, data_len);
        } else {
        // ignore not SYN packet
          rc = false;
        }
      } else {
        // Normal phase: server and client
        Node *sender, *recver;

        if(this->to_server(dir)) {
          // Send data (Clinet => Server)
          sender = &(this->client_);
          recver = &(this->server_);
        } else {
          assert(this->to_client(dir));
          // Send data (Server => Client)
          sender = &(this->server_);
          recver = &(this->client_);
        }

        if (sender->check_seq(seq, ack)) {
          // Valid sequence & ack number
          sender->send(f, seq, ack, data_len);
          recver->recv(f, seq, ack, data_len);
        } else {
          rc = false;
        }
      }

      return rc;
    }
  };

  class TcpSsnDecoder : public Decoder {
  private:
    ev_id EV_EST_, EV_DATA_;
    val_id P_SEG_, P_TO_SERVER_, P_SERVER_STAT_, P_CLIENT_STAT_;
    
    // In order to lookup TCP header.
    val_id P_TCP_HDR_, P_TCP_SEQ_, P_TCP_ACK_, P_TCP_FLAGS_;
    LRUHash *ssn_table_;
    time_t last_ts_;
    static const time_t TIMEOUT = 300;

  public:
    DEF_REPR_CLASS (VarStat, FacStat);

    explicit TcpSsnDecoder (NetDec * nd) : Decoder (nd), last_ts_(0) {
      this->EV_EST_ = nd->assign_event ("tcp_ssn.established",
                                        "TCP session established");
      this->EV_DATA_ = nd->assign_event ("tcp_ssn.data", 
                                         "TCP session segment data");
                                        
      this->P_SEG_ = nd->assign_value ("tcp_ssn.segment", "TCP segment data");
      this->P_TO_SERVER_ = 
        nd->assign_value ("tcp_ssn.to_server", "Packet to server");
      this->P_SERVER_STAT_ =
        nd->assign_value("tcp_ssn.server_stat", "TCP server status",
                         new FacStat());
      this->P_CLIENT_STAT_ =
        nd->assign_value("tcp_ssn.client_stat", "TCP client status",
                         new FacStat());

      this->ssn_table_ = new LRUHash(3600, 0xffff);
    }
    ~TcpSsnDecoder() {
      this->ssn_table_->prog(3600);
      TcpSession *ssn;
      while (nullptr != (ssn = dynamic_cast<TcpSession*>(this->ssn_table_->pop()))) {
        delete ssn;
      }

      delete this->ssn_table_;
    }

    void setup (NetDec * nd) {
      // nothing to do
      this->P_TCP_HDR_ = nd->lookup_value_id("tcp.header");
      this->P_TCP_SEQ_ = nd->lookup_value_id("tcp.seq");
      this->P_TCP_ACK_ = nd->lookup_value_id("tcp.ack");
      this->P_TCP_FLAGS_ = nd->lookup_value_id("tcp.flags");
    };

    static Decoder * New (NetDec * nd) { return new TcpSsnDecoder (nd); }

    void timeout_session(time_t tv_sec) {
      // session timeout 
      if (this->last_ts_ > 0 && this->last_ts_ < tv_sec) {
        this->ssn_table_->prog(tv_sec - this->last_ts_);
      }
      this->last_ts_ = tv_sec;
      TcpSession *outdated_ssn;
      while (nullptr != (outdated_ssn = 
                         dynamic_cast<TcpSession*>(this->ssn_table_->pop()))) {
        if (outdated_ssn->ts() + TIMEOUT < tv_sec) {
          delete outdated_ssn;
        } else {
          this->ssn_table_->put(TIMEOUT, outdated_ssn);
        }
      }

    }

    TcpSession *fetch_session(Property *p) {
      // Lookup TcpSession object from ssn_table_ LRU hash table.
      // If not existing, create new TcpSession and return the one.

      size_t key_len;
      const void *ssn_key = p->ssn_label(&key_len);
      TcpSession *ssn = dynamic_cast<TcpSession*>
        (this->ssn_table_->get(p->hash_value(), ssn_key, key_len));

      if (!ssn) {
        ssn = new TcpSession(ssn_key, key_len, p->hash_value());
        this->ssn_table_->put(TIMEOUT, ssn);
      }

      ssn->set_ts(p->tv_sec());
      return ssn;
    }

    bool decode (Property *p) {
      this->timeout_session(p->tv_sec());

      TcpSession *ssn = this->fetch_session(p);
      size_t data_len = p->remain();

      uint8_t flags = p->value(this->P_TCP_FLAGS_).ntoh <uint8_t> ();
      uint32_t seq = p->value(this->P_TCP_SEQ_).ntoh <uint32_t> ();
      uint32_t ack = p->value(this->P_TCP_ACK_).ntoh <uint32_t> ();

      static const bool DBG = false;
      debug(DBG, "data: %zd", data_len);

      if (ssn->update(flags, seq, ack, data_len, p->dir())) {
        bool to_server = ssn->to_server(p->dir());
        byte_t *data = p->payload(data_len);
        if(to_server) {
          debug(DBG, "C->S");
        } else {
          debug(DBG, "S->C");
        }
        p->copy(this->P_TO_SERVER_, &to_server, sizeof(to_server));

        if (ssn->is_data_available(p->dir())) {
          if (data_len > 0) {
            if(to_server) {
              debug(DBG, "seg_data: %zd", data_len);
            } else {
              debug(DBG, "seg_data: %zd", data_len);
            }
            p->set(this->P_SEG_, data, data_len);
            p->push_event (this->EV_DATA_);
          }
        }
      }

      TcpStat server = ssn->server_stat();
      TcpStat client = ssn->client_stat();
      p->copy(this->P_SERVER_STAT_, &server, sizeof(server));
      p->copy(this->P_CLIENT_STAT_, &client, sizeof(client));
      
      // set data to property
      // p->set (this->P_SRC_PORT_, &(hdr->src_port_), sizeof (hdr->src_port_));

      // push event
      // p->push_event (this->EV_PKT_);


      return true;
    }
  };

  std::string TcpSsnDecoder::VarStat::repr () const {
    std::string str;
    TcpStat *s = reinterpret_cast<TcpStat*>(this->ptr());

    switch (*s) {
    case TcpStat::CLOSED: str = "CLOSED"; break;
    case TcpStat::LISTEN: str = "LISTEN"; break;
    case TcpStat::SYN_SENT: str = "SYN_SENT"; break;
    case TcpStat::SYN_RCVD: str = "SYN_RCVD"; break;
    case TcpStat::ESTABLISHED: str = "ESTABLISHED"; break;
    case TcpStat::TIME_WAIT: str = "TIME_WAIT"; break;
    case TcpStat::CLOSING: str = "CLOSING"; break;
    }
    
    return str;
  }

  
  INIT_DECODER (tcp_ssn, TcpSsnDecoder::New);
}  // namespace swarm
