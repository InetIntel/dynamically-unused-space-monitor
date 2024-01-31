#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"
#include "include/constants.p4"


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<1>>(GLOBAL_TABLE_ENTRIES) global_table;
    register<bit<1>>(GLOBAL_TABLE_ENTRIES) flag_table;
    bit<1> g_value;
    bit<1> f_value;
    
    register<bit<16>>(DARK_TABLE_ENTRIES) dark_table;
    bit<16> d_value;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action calc_idx(bit<GLOBAL_TABLE_INDEX_WIDTH> base_idx, bit<6> pfx_len) {
        bit<32> mask = 0xffffffff;
        mask = mask << ((bit<6>)32 - pfx_len);
        mask = ~mask;

        bit<32> offset = meta.addr & mask;
        //offset = offset >> 8; // change according to granularity
        meta.idx = base_idx + (bit<GLOBAL_TABLE_INDEX_WIDTH>) offset;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    table monitored {
        key = {
            meta.addr: lpm;
        }
        actions = {
            calc_idx;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    action set_incoming(){
        meta.addr = hdr.ipv4.dstAddr;
        meta.incoming = 1;
    }

    action set_outgoing(){
        meta.addr = hdr.ipv4.srcAddr;
        meta.outgoing = 1;
    }

    table ports {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_incoming;
            set_outgoing;
            @defaultonly NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    apply {
        // Two variables to account for future cases of packets that cant be classified (packets from the logging machine, etc).
        meta.incoming = 0;
        meta.outgoing = 0;
        // Whether to forward the packet or not
        meta.ignore = 0;

        if (hdr.ipv4.isValid()){
            if (hdr.ctl.isValid()){
                meta.addr = hdr.ctl.targetAddr;
                meta.outgoing = 1;
            }
            else {
                ports.apply();
            }

            if (monitored.apply().hit){
                if (meta.outgoing == (bit<1>) 1){
                    global_table.write((bit<32>) meta.idx, (bit<1>)1);
                    @atomic{
                        flag_table.read(f_value, (bit<32>)meta.idx);
                        meta.notify = ~ f_value;
                        flag_table.write((bit<32>)meta.idx, (bit<1>)1);
                    }
                    if (hdr.ctl.isValid()){
                        meta.ignore = (bit<1>)1;
                        drop();
                    }
                    else if (meta.notify == (bit<1>)1){
                        clone3(CloneType.I2E, 100, meta);
                    }
                }
                else if (meta.incoming == (bit<1>)1){
                    global_table.read(g_value, (bit<32>)meta.idx);
                    flag_table.read(f_value, (bit<32>)meta.idx);

                    if (g_value == (bit<1>)0 && f_value == (bit<1>)0){
                        bit<32> dstIP = hdr.ipv4.dstAddr>>8; //configurable
                        bit<10> h_idx;
                        hash(h_idx,
                            HashAlgorithm.crc16,
                            (bit<10>)0,
                            {dstIP},
                            (bit<11>)DARK_TABLE_ENTRIES);
                        // meta.ignore = (bit<1>)1; // up to operators to drop or forward
                        @atomic{
                            dark_table.read(d_value, (bit<32>)h_idx);
                            
                            if (d_value == (bit<16>)2047){
                                dark_table.write((bit<32>)h_idx, (bit<16>)COUNTER_THRESHOLD);
                            }
                            else{
                                dark_table.write((bit<32>)h_idx, (bit<16>)(d_value + (bit<16>)1));
                            }
                            
                        }

                        if (d_value < (bit<16>)COUNTER_THRESHOLD){
                            //meta.egress_spec = LOG_PORT;
                        }
                        else{
                            if ((d_value & (bit<16>)(RATE_LIMIT-1)) == (bit<16>)0){ // mod RATE_LIMIT
                                //meta.egress_spec = LOG_PORT;
                        .       clone3(CloneType.I2E, 200, meta);
                            }
                            else{
                                //drop();
                            }
                        }
                    }
                }
            }    
            if (meta.ignore == (bit<1>)0){
                // Basic forwarding logic
                ipv4_lpm.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop_r(macAddr_t dstMACAddr, ip4Addr_t dstIpAddr){
        hdr.ethernet.dstAddr = dstMACAddr;
        hdr.ipv4.dstAddr = dstIpAddr;
    }

    table mcast_routers{
        key = {
            standard_metadata.egress_rid: exact;
        }
        actions = {
            set_nhop_r;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        if(standard_metadata.egress_rid != 0){
            mcast_routers.apply();
            hdr.ipv4.protocol = (bit<8>)ip_protocol_t.CTL;
            hdr.ipv4.ttl = 255;
            hdr.ipv4.totalLen = 24;
            hdr.ctl.setValid();
            hdr.ctl.targetAddr = meta.addr;
            truncate(38);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;