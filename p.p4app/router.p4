#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT = 0x1;

const bit<16> ARP_OP_REQUEST = 0x1;
const bit<16> ARP_OP_REPLY = 0x2;

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<16> TYPE_CPU_METADATA = 0x80b;

const bit<8> TYPE_ICMP = 0x1;
const bit<8> TYPE_OSPF = 0x59;

const bit<8> TYPE_HELLO = 0x1;
const bit<8> TYPE_LSU = 0x4;

const bit<8> ICMP_ECHO_REQUEST = 0x8;
const bit<8> ICMP_ECHO_REPLY   = 0;

header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     ethType;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_t   srcAddr;
    ip4Addr_t   dstAddr;

}

header arp_t {
    bit<16>     hType;
    bit<16>     pType;
    bit<8>      hLen;
    bit<8>      pLen;
    bit<16>     oper;
    macAddr_t   srcMAC;
    ip4Addr_t   srcIP;
    macAddr_t   dstMAC;
    ip4Addr_t   dstIP;
}

header pwospf_t {
    bit<8>      version;
    bit<8>      type;
    bit<16>     length;
    bit<32>     routerID;
    bit<32>     areaID;
    bit<16>     checksum;
    bit<16>     auType;
    bit<64>     auth;
}

header hello_t {
    bit<32>     netMask;
    bit<16>     helloInt;
    bit<16>     padding;
}

header lsu_t {
    bit<16>     sequence;
    bit<16>     ttl;
    bit<32>     adv_number;
    # TODO: ?create header stack with lsu_ad? might not be possible
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

header cpu_metadata_t {
    bit<1>      fromCpu;
    bit<5>      opType;
    port_t      srcPort;
    port_t      dstPort;
    bit<16>     origEthType;
    ip4Addr_t   nextHop;
}

struct headers_t {
    ethernet_t      ethernet;
    cpu_metadata_t  cpu_metadata;
    arp_t           arp;
    ipv4_t          ipv4;
    icmp_t          icmp;
    pwospf_t        pwospf;
    hello_t         hello;
    lsu_t           lsu;
}

struct my_metadata_t {}

parser parser_impl (packet_in packet,
                    out headers_t hdr,
                    inout my_metadata_t my_metadata,
                    inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType){
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_OSPF: parse_pwospf;
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
      packet.extract(hdr.icmp);
      transition accept;
    }

    state parse_pwospf {
        packet.extract(hdr.pwospf);
        transition select(hdr.pwospf.type) {
            TYPE_HELLO: parse_hello;
            TYPE_LSU: parse_lsu;
            default: accept;
        }
    }

    state parse_hello {
        packet.extract(hdr.hello);
        transition accept;
    }

    state parse_lsu {
        packet.extract(hdr.lsu);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEthType){
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }
}

control ingress_control(inout headers_t hdr,
                        inout my_metadata_t my_metadata,
                        inout standard_metadata_t standard_metadata) {
    //local variables
    port_t dstPort = 0;
    ip4Addr_t next_hop = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(ip4Addr_t nhop, port_t egress_port) {
        standard_metadata.egress_spec = egress_port;
        next_hop = nhop;
        if(next_hop == 0){
            next_hop = hdr.ipv4.dstAddr;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    action set_dmac(macAddr_t mac_dest) {
        hdr.ethernet.dstAddr = mac_dest;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr:lpm;
        }
        actions = {
            set_nhop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    action set_sintf(port_t egress_port) {
        standard_metadata.egress_spec = egress_port;
        next_hop = hdr.ipv4.dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    action cpu_metadata_encap(bit<5> reasonID) {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.srcPort = standard_metadata.ingress_port;
        hdr.cpu_metadata.origEthType = hdr.ethernet.ethType;
        hdr.ethernet.ethType = TYPE_CPU_METADATA;
        hdr.cpu_metadata.opType = reasonID;
    }

    action send_to_cpu(bit<5> reasonID){

        standard_metadata.egress_spec = CPU_PORT;
        cpu_metadata_encap(reasonID);
    }

    action multicast(bit<16> mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    table local_ip_table {
        key = {
            hdr.ipv4.dstAddr:exact;
        }
        actions = {
            set_sintf;
            multicast;
            send_to_cpu;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }


    action cpu_metadata_decap() {
        hdr.ethernet.ethType = hdr.cpu_metadata.origEthType;
        hdr.cpu_metadata.setInvalid();
    }

    action request_arp() {
        port_t temp = standard_metadata.egress_spec;
        send_to_cpu(1);
        hdr.cpu_metadata.nextHop = next_hop;
        hdr.cpu_metadata.dstPort = temp;
    }

    table arp_table {
        key = {
            next_hop:exact;
        }
        actions = {
            set_dmac;
            request_arp;
            NoAction;
        }
        size = 1024;
        default_action = request_arp();
    }

    action reply(macAddr_t intfAddr) {
        hdr.arp.dstMAC = hdr.arp.srcMAC;
        ip4Addr_t temp = hdr.arp.dstIP;
        hdr.arp.dstIP = hdr.arp.srcIP;
        hdr.arp.srcIP = temp;
        hdr.arp.srcMAC = intfAddr;
        hdr.arp.oper = ARP_OP_REPLY;

        hdr.ethernet.srcAddr = intfAddr;
        hdr.ethernet.dstAddr = hdr.arp.dstMAC;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table arp_reply_table {
        key = {
            hdr.arp.dstIP:exact;
        }
        actions = {
            reply;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }


    apply {
        if(hdr.cpu_metadata.fromCpu  == 1 && hdr.cpu_metadata.isValid()){
            if(hdr.cpu_metadata.dstPort > 1){
                standard_metadata.egress_spec = hdr.cpu_metadata.dstPort;
            }
            cpu_metadata_decap();
        }
        if(standard_metadata.egress_spec < 1){
            if(hdr.ipv4.isValid()) {
                if(hdr.ipv4.ttl>0){
                  if(local_ip_table.apply().miss){
                      ipv4_lpm.apply();
                  }
                  if(standard_metadata.egress_spec == 1 && standard_metadata.ingress_port != 1){
                    if(hdr.icmp.isValid() && hdr.icmp.type == 8 && hdr.icmp.code == 0) {
                        send_to_cpu(4);
                    }else if(hdr.pwospf.isValid()){
                        if(hdr.hello.isValid()){
                            send_to_cpu(5);
                        }else if(hdr.lsu.isValid()){
                            send_to_cpu(6);
                        }
                    }
                  }else if(standard_metadata.egress_spec >1){
                    arp_table.apply();
                  }
                }else{
                    send_to_cpu(3);
                }
            }else if(hdr.arp.isValid()){
                if(hdr.arp.oper == ARP_OP_REQUEST){
                  arp_reply_table.apply();
                }else if(hdr.arp.oper == ARP_OP_REPLY){
                  send_to_cpu(2);
                }
            }else{
              drop();
            }
        }
    }
}

control egress_control(inout headers_t hdr,
                        inout my_metadata_t my_metadata,
                        inout standard_metadata_t standard_metadata) {
    action set_smac(macAddr_t smac) {
        hdr.ethernet.srcAddr = smac;
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }
    table mac_rewriting_table {
        actions = {
            set_smac;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            mac_rewriting_table.apply();
        }else {
            drop();
        }
    }
}

control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.pwospf);
        packet.emit(hdr.hello);
        packet.emit(hdr.lsu);
    }
}

control verify_checksum_control(inout headers_t hdr,
                                inout my_metadata_t my_metadata) {
    apply {
        verify_checksum(hdr.ipv4.isValid(),
        { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control compute_checksum_control(inout headers_t hdr,
                                 inout my_metadata_t my_metadata) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

V1Switch(parser_impl(),
         verify_checksum_control(),
         ingress_control(),
         egress_control(),
         compute_checksum_control(),
         deparser()) main;
