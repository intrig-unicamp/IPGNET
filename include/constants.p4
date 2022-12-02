/*********************  C O N S T A N T S   D E F I N I T I O N *****************************************/

const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

const bit<16> GTP_UDP_PORT     = 2152;
const bit<16> UDP_PORT_VXLAN   = 4789;

const bit<32> MAC_LEARN_RECEIVER = 1;
const bit<32> ARP_LEARN_RECEIVER = 1025;

typedef bit<9> port_t;
const port_t CPU_PORT = 255;

#define TYPE_TELEMETRY 31

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    ARP  = 0x0806,
    TPID = 0x8100,
    IPV6 = 0x86DD,
    MPLS = 0x8847
}

const bit<16> maximum = 65535;


/**** pre-defined parameters for HH detection ***/
const bit<16>  IPG_INIT  = 1600;  // for 5 Mbps HH threhsold
const bit<16>  CONST     = 20;    // contant rate linear increase of weighted IPG 
const bit<16>  TAU_TH    = 300;   // tau threshold to decide HHs 
const bit<32>  WRAPTIME  = 2147483648;  // in microseconds
const  bit<5>  QID_LP    = 7;   
const  bit<5>  QID_HP    = 1; 
typedef bit<11>rSize;             // size of register 
