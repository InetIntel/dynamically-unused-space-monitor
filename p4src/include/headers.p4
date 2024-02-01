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

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

enum bit<16> ether_type_t {
    IPV4 = 0x0800
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

enum bit<8> ip_protocol_t{
    UDP = 17, 
    TCP = 6,
    CTL = 146
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header ctl_t{
    bit<32> targetAddr;
}

struct metadata {
    bit<32> addr;
    bit<22> idx;
    bit<1> incoming;
    bit<1> outgoing;
    bit<1> ignore;
    bit<1> notify;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    ctl_t        ctl; 
}


