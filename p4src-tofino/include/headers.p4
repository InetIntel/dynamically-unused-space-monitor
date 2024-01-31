typedef bit<48> mac_addr_t;
typedef bit<8> header_type_t;

enum bit<16> ether_type_t {
    IPV4 = 0x0800
}

header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

typedef bit<32> ipv4_addr_t;

enum bit<8> ip_protocol_t{
    UDP = 17, 
    TCP = 6,
    CTL = 146
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    ip_protocol_t protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ctl_h {
    ipv4_addr_t targetAddr;
}

header darknet_control_mirror_h {
    header_type_t header_type;
    ipv4_addr_t addr;
}

header normal_h {
    header_type_t header_type;
}

struct my_ingress_metadata_t {
    ipv4_addr_t addr;
    bit<22> idx;
    bit<22> offset;
    bit<1> incoming;
    bit<1> outgoing;
    bit<1> ignore;
    bit<1> notify;
    header_type_t mirror_header_type;
    normal_h bridge;
    MirrorId_t mirror_session;
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    ctl_h        ctl;
}

struct my_egress_headers_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    ctl_h ctl;
}

struct my_egress_metadata_t {
    header_type_t header_type;
    ipv4_addr_t addr;
}

const header_type_t HEADER_NORMAL = 0;
const header_type_t HEADER_CONTROL = 8w2;
const header_type_t HEADER_MIRROR = 8w1;
typedef bit<22> global_reg_index_t;
typedef bit<10> dark_reg_index_t;
typedef bit<8> mcast_index_t;