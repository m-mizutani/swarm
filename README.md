Swarm
===========================
Swarm is the **C++ based lightweight and high-speed network traffic decoding library**.

Features
---------------------------

- Zero-copy based high-speed decoding of packet
- Extracting parameters of network protocol ([example](./example/extract_data.cc))
- Extendable protocol decoding module ([example](./example/original_decoder.cc))

Required compiler & libraries
---------------------------

- C++11
- libpcap
- pthread

Install
---------------------------

    % cd swarm
    % cmake . && make
    % sudo make install

Sample
---------------------------

### Capture DNS packet from interface eth0

    #include <swarm.h>
    #include <iostream>
    
    class DnsHandler : public swarm::Handler {
    public:
      void recv (swarm::ev_id ev, const swarm::Property &p) {
        // print domain name of dns query
        std::cout << p.value("dns.qd_name").repr () << std::endl;
      }
    };
    
    int main () {
      swarm::SwarmDev *sw = new swarm::SwarmDev("eth0");
      sw->set_handler ("dns.packet", new DnsHandler());
      sw->start ();
    }

### Capture IPv4 source addresses from pcap file "data.pcap"

    #include <swarm.h>
    #include <set>
    
    class IPv4SrcHandler : public swarm::Handler {
    public:
      std::set<std::string> ipaddr_set_;
      void recv (swarm::ev_id ev, const swarm::Property &p) {
        this->ipaddr_set_.insert(p.value("ipv4.src"));
      }
    };
    
    int main () {
      swarm::SwarmDev *sw = new swarm::SwarmDev("eth0");
      sw->set_handler ("ipv4.packet", new IPv4SrcHandler());
      sw->start ();
    }

### Show a number of packets of IPv4 per one second

    #include<swarm.h>
    #include<iostream>
    
    class Wathcer : public swarm::Task, public swarm::Handler {
    public:
      int count_;
      Wathcer() : count_(0) {}
      void recv (swarm::ev_id ev, const swarm::Property &p) {
        this->count_++;
      }
      void exec (const struct timespec &ts) {
        std::cout << this->count_ << std::endl;
        this->count_ = 0;
      }
    };
    
    int main () {
      swarm::SwarmDev *sw = new swarm::SwarmDev("en0");
      Wathcer *w = new Wathcer();
      sw->set_handler("ipv4.packet", w);
      sw->set_periodic_task(w, 1.);
      sw->start ();
    }
    

More examples are available in [example directory](https://github.com/m-mizutani/swarm/tree/master/example).
