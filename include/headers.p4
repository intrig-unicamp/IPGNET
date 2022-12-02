#include <core.p4>
#include <tna.p4>

#include "constants.p4"
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

header ipv4_h {
    //bit<4>       version;
    bit<8>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> csum;
}

header telemetry_t{
    bit<32> ipv4_srcAddr;
    bit<32> ipv4_dstAddr;
    bit<16> tcp_sport;
    bit<16> tcp_dport;
    bit<8>  protocol;
    bit<48> ingress_timestamp;
    bit<48> egress_timestamp; 
    bit<19> enqQdepth;
    bit<19> deqQdepth; 
    bit<2> padding; // 238 bits of telemetry data + 2 bits of padding + 16 bits of IPOption header = 256 bits (multiple of 32)
} 

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header ipg_t {
	bit<16> IPGw;
	bit<16> IPGw1;
	bit<16> IPGw2;
	bit<16> IPGw3;
	bit<16> seq;
	bit<48> ts;
	bit<16> pad;
	bit<32> new;
}

/* Local metadata */
struct hash_metadata_t {
    bit<32>  flowId;
    bit<1>   IPGflag;
    bit<48>  TS;
    bit<16>  tauFlag;
    bit<8>   FlowIdFlag;
    bit<8>   IPGw_flag;
	bit<16>  vai;
    bit<32>  TSlastComp;
    bit<32>  TSlast;
    bit<16>  Diff;
    bit<16>  IPGw;
    bit<16>  tau;
    bit<16>  IPGc;
    bit<32>  TSc;
    bit<16>  IPGcComp;
    bit<11>  mIndex;
    bit<16>  l4_sport;
    bit<16>  l4_dport;
    bit<8>   resubmit_type;
	bit<28> padd;
}

struct header_t {
    ethernet_h   	ethernet;
    ipv4_h       	ipv4;
    ipv4_option_t 	ipv4_option;
    ipg_t   		ipg;
    tcp_t 			tcp;
    udp_t			udp;
}


struct ingress_metadata_t {
    hash_metadata_t hash_meta;
}

struct egress_metadata_t {
	hash_metadata_t hash_meta;
}
