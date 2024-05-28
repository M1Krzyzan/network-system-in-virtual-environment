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
const bit<16> TYPE_CPU_METADATA = 0x80a;

header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     ethType;
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

header cpu_metadata_t {
    bit<7>      fromCpu;
    port_t      srcPort;
    bit<16>     etherType;
}

struct headers_t {
    ethernet_t      ethernet;
    cpu_metadata_t  cpu_metadata;
    arp_t           arp;
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
        transition select(hdr.ethernet.ethType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default:accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.etherType) {
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

control ingress_control(inout headers_t hdr,
                        inout my_metadata_t my_metadata,
                        inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(port_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    action multicast(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    table l2_forwarding {
        key = {
            hdr.ethernet.dstAddr:exact;
        }
        actions = {
            forward;
            multicast;
            drop;
        }
        size = 1024;
        default_action = multicast(1);
    }

    action cpu_metadata_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.srcPort = standard_metadata.ingress_port;
        hdr.cpu_metadata.etherType = hdr.ethernet.ethType;
        hdr.ethernet.ethType = TYPE_CPU_METADATA;

    }

    action send_to_cpu(){
        if(standard_metadata.mcast_grp>0){
          standard_metadata.mcast_grp = 0;
        }
        standard_metadata.egress_spec = 1;
        cpu_metadata_encap();
    }


    action cpu_metadata_decap() {
        hdr.ethernet.ethType = hdr.cpu_metadata.etherType;
        hdr.cpu_metadata.setInvalid();
    }

    table learned_src {
        key = {
            hdr.ethernet.srcAddr:exact;
        }
        actions = {
            NoAction;
            send_to_cpu;
        }
        size = 1024;
        default_action = send_to_cpu;
    }

    apply {
    if(hdr.cpu_metadata.fromCpu == 1 && hdr.cpu_metadata.isValid()){
        cpu_metadata_decap();
    }

    if(hdr.ethernet.isValid()) {
        l2_forwarding.apply();
        learned_src.apply();
    }
    }
}

control egress_control(inout headers_t hdr,
                        inout my_metadata_t my_metadata,
                        inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }
    apply {
        if(standard_metadata.egress_port == standard_metadata.ingress_port){
            drop();
        }
    }
}

control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
    }
}

control verify_checksum_control(inout headers_t hdr,
                                inout my_metadata_t my_metadata) {
    apply {
    }
}

control compute_checksum_control(inout headers_t hdr,
                                 inout my_metadata_t my_metadata) {
    apply {
    }
}

V1Switch(parser_impl(),
         verify_checksum_control(),
         ingress_control(),
         egress_control(),
         compute_checksum_control(),
         deparser()) main;
