#include <core.p4>
#include <tna.p4>

#include "headers.p4"

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser SwitchIngressParser(
        packet_in packet,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

	state start {
		packet.extract(ig_intr_md);
		packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
	}

	state parse_ethernet {
    	packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4:  parse_ipv42;
            default: accept;
        }
     }
	
	state parse_ipv4 {
    	packet.extract(hdr.ipv4);
			transition select(hdr.ipv4.protocol) {
				IPPROTO_UDP  : parse_udp;
				IPPROTO_TCP  : parse_tcp;
				default      : reject;
			}
     	}

	//new
	state parse_ipv42 {
        packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.ihl[3:0]){
			5	: parse_protocol;
			default : parse_ipv4_option;
		}
	}

	state parse_protocol {
		transition select(hdr.ipv4.protocol) {
			IPPROTO_UDP  : parse_udp;
			IPPROTO_TCP  : parse_tcp;
			default      : reject;
		}
	}

	state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option){
            TYPE_TELEMETRY:  parse_int;
            default: parse_int;
        }
     }

	state parse_int {
		packet.extract(hdr.ipg);
		transition parse_protocol;
	}

	//finish new
	state parse_tcp {
        packet.extract(hdr.tcp);
        ig_md.hash_meta.l4_sport = hdr.tcp.srcPort;
        ig_md.hash_meta.l4_dport = hdr.tcp.dstPort;
        transition accept;
	}
     
    state parse_udp {
        packet.extract(hdr.udp);
        ig_md.hash_meta.l4_sport = hdr.udp.srcPort;
        ig_md.hash_meta.l4_dport = hdr.udp.dstPort;
        transition accept; 
       }
}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {


    apply {

        /*packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);*/

        //packet.emit(hdr);
		
		//pkt.emit(hdr);

		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.ipv4_option);
		pkt.emit(hdr.ipg);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.udp);
  }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------

parser SwitchEgressParser(
        packet_in packet,
        out header_t hdr,
        out ingress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

	state start {
		packet.extract(eg_intr_md);
		//packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
	}

	state parse_ethernet {
    	packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4:  parse_ipv42;
            default: accept;
        }
     }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP  : parse_udp;
            IPPROTO_TCP  : parse_tcp;
            default      : accept;
        }
     }

	//new

	state parse_ipv42 {
        packet.extract(hdr.ipv4);
		transition parse_ipv4_option;        
		/*
		transition select(hdr.ipv4.ihl) {
	    	5		: 	parse_protocol;
			default: parse_ipv4_option;
		}*/
    }
	
	state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option){
            TYPE_TELEMETRY:  parse_int;
            default: parse_int;
        }
     }

	state parse_int {
		packet.extract(hdr.ipg);
		transition parse_protocol;
	}	

	state parse_protocol {
		transition select(hdr.ipv4.protocol){
			IPPROTO_UDP  : parse_udp;
            IPPROTO_TCP  : parse_tcp;
			default      : accept;
		}
	}


	//finish

	state parse_tcp {
        packet.extract(hdr.tcp);
        eg_md.hash_meta.l4_sport = hdr.tcp.srcPort;
        eg_md.hash_meta.l4_dport = hdr.tcp.dstPort;
        transition accept;
    }
     
	state parse_udp {
        packet.extract(hdr.udp);
        eg_md.hash_meta.l4_sport = hdr.udp.srcPort;
        eg_md.hash_meta.l4_dport = hdr.udp.dstPort;
        transition accept; 
	}


	
}


// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out packet,
        inout header_t hdr,
        in ingress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
       //Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;

	apply {


		packet.emit(hdr);
    }

}
