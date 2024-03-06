// This software is Copyright (c) 2024 Georgia Tech Research Corporation. All
// Rights Reserved. Permission to copy, modify, and distribute this software and
// its documentation for academic research and education purposes, without fee,
// and without a written agreement is hereby granted, provided that the above
// copyright notice, this paragraph and the following three paragraphs appear in
// all copies. Permission to make use of this software for other than academic
// research and education purposes may be obtained by contacting:
//
//  Office of Technology Licensing
//  Georgia Institute of Technology
//  926 Dalney Street, NW
//  Atlanta, GA 30318
//  404.385.8066
//  techlicensing@gtrc.gatech.edu
//
// This software program and documentation are copyrighted by Georgia Tech
// Research Corporation (GTRC). The software program and documentation are 
// supplied "as is", without any accompanying services from GTRC. GTRC does
// not warrant that the operation of the program will be uninterrupted or
// error-free. The end-user understands that the program was developed for
// research purposes and is advised not to rely exclusively on the program for
// any reason.
//
// IN NO EVENT SHALL GEORGIA TECH RESEARCH CORPORATION BE LIABLE TO ANY PARTY FOR
// DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
// LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
// EVEN IF GEORGIA TECH RESEARCH CORPORATION HAS BEEN ADVISED OF THE POSSIBILITY
// OF SUCH DAMAGE. GEORGIA TECH RESEARCH CORPORATION SPECIFICALLY DISCLAIMS ANY
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
// HEREUNDER IS ON AN "AS IS" BASIS, AND  GEORGIA TECH RESEARCH CORPORATION HAS
// NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
// MODIFICATIONS.

// ETHERNET
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
    CTL = 146,
    MIRROR = 147
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
    bit<21> idx;
    bit<21> offset;
    bit<14> dark_idx;
    bit<1> incoming;
    bit<1> outgoing;
    bit<1> ignore;
    bit<1> notify;
    bit<1> pos;
    header_type_t mirror_header_type;
    normal_h bridge;
    MirrorId_t mirror_session;
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    ctl_h        ctl;
}

struct my_egress_metadata_t {
    header_type_t header_type;
    ipv4_addr_t addr;
}

struct my_egress_headers_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    ctl_h ctl;
}

const header_type_t HEADER_NORMAL = 0;
const header_type_t HEADER_CONTROL = 8w2;
const header_type_t HEADER_MIRROR = 8w1;
typedef bit<21> global_reg_index_t;
typedef bit<10> dark_reg_index_t;
typedef bit<8> mcast_index_t;