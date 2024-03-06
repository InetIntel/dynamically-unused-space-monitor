# This software is Copyright (c) 2024 Georgia Tech Research Corporation. All
# Rights Reserved. Permission to copy, modify, and distribute this software and
# its documentation for academic research and education purposes, without fee,
# and without a written agreement is hereby granted, provided that the above
# copyright notice, this paragraph and the following three paragraphs appear in
# all copies. Permission to make use of this software for other than academic
# research and education purposes may be obtained by contacting:
#
#  Office of Technology Licensing
#  Georgia Institute of Technology
#  926 Dalney Street, NW
#  Atlanta, GA 30318
#  404.385.8066
#  techlicensing@gtrc.gatech.edu
#
# This software program and documentation are copyrighted by Georgia Tech
# Research Corporation (GTRC). The software program and documentation are 
# supplied "as is", without any accompanying services from GTRC. GTRC does
# not warrant that the operation of the program will be uninterrupted or
# error-free. The end-user understands that the program was developed for
# research purposes and is advised not to rely exclusively on the program for
# any reason.
#
# IN NO EVENT SHALL GEORGIA TECH RESEARCH CORPORATION BE LIABLE TO ANY PARTY FOR
# DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
# LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
# EVEN IF GEORGIA TECH RESEARCH CORPORATION HAS BEEN ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE. GEORGIA TECH RESEARCH CORPORATION SPECIFICALLY DISCLAIMS ANY
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
# HEREUNDER IS ON AN "AS IS" BASIS, AND  GEORGIA TECH RESEARCH CORPORATION HAS
# NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
# MODIFICATIONS.

import os
import sys
import pdb
import logging
import math

SDE_INSTALL   = os.environ['SDE_INSTALL']

PYTHON3_VER   = '{}.{}'.format(
    sys.version_info.major,
    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER,
                             'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

LOG_PORT = 6
# LOG_PORT = 140 # 2
THRESHOLD = 1024
RECIRCULATE_PORT = 68
NUM_PIPES = 2

import bfrt_grpc.client as gc
from tabulate import tabulate
import argparse, time, ipaddress
from aggregate6 import aggregate
from radix import Radix
import threading

class LocalClient:
    def __init__(self, time_interval, global_table_size, dark_meter_size, alpha, monitored_path, ports,\
                max_pkt_rate, max_byte_rate, avg_pkt_rate, avg_byte_rate):        
        self.time_interval = time_interval*60 # convert to sec
        self.global_table_size = global_table_size
        self.dark_meter_size = dark_meter_size
        self.alpha = alpha
        self.counters = [self.alpha]*self.global_table_size
        self.monitored_path = monitored_path
        self.index_prefix_mapping = []
        self.prefix_index_mapping = Radix()
        self.dark_prefix_index_mapping = dict()
        self.ports = ports

        self.max_pkt_rate = max_pkt_rate
        self.max_byte_rate = max_byte_rate
        self.avg_pkt_rate = avg_pkt_rate
        self.avg_byte_rate = avg_byte_rate
        # max pkt rate per address
        self.max_pkt_rate_addr = round(self.max_pkt_rate / self.global_table_size, 3)
        self.max_byte_rate_addr = round(self.max_byte_rate / self.global_table_size, 3)
        self.avg_pkt_rate_addr = round(self.avg_pkt_rate / self.global_table_size, 3)
        self.avg_byte_rate_addr = round(self.avg_byte_rate / self.global_table_size, 3)

        self.lock = threading.Lock()
        self._setup()

    def parse_monitored(self, path):
        monitored_prefixes = []
        with open(path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                monitored_prefixes.append(line[:-1])
        return monitored_prefixes

    def _setup(self):
        bfrt_client_id = 0

        self.interface = gc.ClientInterface(
            grpc_addr = 'localhost:50052', # 130.207.238.85
            client_id = bfrt_client_id,
            device_id = 0,
            num_tries = 1)

        self.bfrt_info = self.interface.bfrt_info_get()
        self.dev_tgt = gc.Target(0)
        print('The target runs the program ', self.bfrt_info.p4_name_get())

        self.ports_table = self.bfrt_info.table_get('pipe.Ingress.ports')
        self.monitored_table = self.bfrt_info.table_get('pipe.Ingress.monitored')
        self.monitored_table.info.key_field_annotation_add('meta.addr', 'ipv4')
        self.global_table = self.bfrt_info.table_get('pipe.Ingress.global_table')
        self.flag_table = self.bfrt_info.table_get('pipe.Ingress.flag_table')
        self.dark_meter = self.bfrt_info.table_get('pipe.Ingress.dark_meter')
        self.dark_global_meter = self.bfrt_info.table_get('pipe.Ingress.dark_global_meter')        
        self.interface.bind_pipeline_config(self.bfrt_info.p4_name_get())
    # def _setup_tables(self):
        self.add_mirroring([5, 5, 6], 1, 3)  # set up mirroring
        monitored_prefixes = self.parse_monitored(self.monitored_path)   # populate monitored table
        self.populate_monitored(monitored_prefixes)
        self.add_ports(self.ports)

    def set_rates(self):
        # set global rate
        print(self.max_pkt_rate)
        _key = self.dark_global_meter.make_key([gc.KeyTuple('$METER_INDEX', 0)])
        _data = self.dark_global_meter.make_data(
            [gc.DataTuple('$METER_SPEC_CIR_PPS', self.avg_pkt_rate),
             gc.DataTuple('$METER_SPEC_PIR_PPS', self.max_pkt_rate),
             gc.DataTuple('$METER_SPEC_CBS_PKTS', 100),
             gc.DataTuple('$METER_SPEC_PBS_PKTS', 100)])
        try:
                self.dark_global_meter.entry_add(self.dev_tgt, [_key], [_data])
        except:
            pass

        # only for packet rate for now
        prefix_max_pkt_rate = math.ceil(self.max_pkt_rate_addr * 256) # per /24
        prefix_avg_pkt_rate = math.ceil(self.avg_pkt_rate_addr * 256) # per /24

        key_field_list = []
        data_field_list = []
        for i in range(len(self.dark_prefix_index_mapping)):
            # set rate for /24
            key_field_list.append(self.dark_meter.make_key([gc.KeyTuple('$METER_INDEX', i)]))
            data_field_list.append(self.dark_meter.make_data(
            [gc.DataTuple('$METER_SPEC_CIR_PPS', prefix_avg_pkt_rate),
             gc.DataTuple('$METER_SPEC_PIR_PPS', prefix_max_pkt_rate),
             gc.DataTuple('$METER_SPEC_CBS_PKTS', 100),
             gc.DataTuple('$METER_SPEC_PBS_PKTS', 100)]))
        try:
            self.dark_meter.entry_add(self.dev_tgt, key_field_list, data_field_list)
        except:
            pass

    def update_rates(self, inactive_pfxs, inactive_addr):
        addr_avg_pkt_rate = math.ceil(self.avg_pkt_rate / inactive_addr) # per /24
        addr_max_pkt_rate = math.ceil(self.max_pkt_rate / inactive_addr) # per /24

        key_field_list = []
        data_field_list = []
        for inactive_pfx, in_addr in inactive_pfxs.items():
            prefix_max_pkt_rate = math.ceil(addr_max_pkt_rate * in_addr) # per /24
            prefix_avg_pkt_rate = math.ceil(addr_avg_pkt_rate * in_addr) # per /24
            idx = self.dark_prefix_index_mapping[inactive_pfx]
            key_field_list.append(self.dark_meter.make_key([gc.KeyTuple('$METER_INDEX', idx)]))
            data_field_list.append(self.dark_meter.make_data(
            [gc.DataTuple('$METER_SPEC_CIR_PPS', prefix_avg_pkt_rate),
             gc.DataTuple('$METER_SPEC_PIR_PPS', prefix_max_pkt_rate),
             gc.DataTuple('$METER_SPEC_CBS_PKTS', 100),
             gc.DataTuple('$METER_SPEC_PBS_PKTS', 100)]))
        try:
            self.dark_meter.entry_add(self.dev_tgt, key_field_list, data_field_list)
        except:
            pass
            
    def add_ports(self, ports):
        for port in ports['incoming']:
            _keys = self.ports_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port)])
            _data = self.monitored_table.make_data([], 'Ingress.set_incoming')
            try:
                self.ports_table.entry_add(self.dev_tgt, [_keys], [_data])
            except:
                pass

        for port in ports['outgoing']:
            _keys = self.ports_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port)])
            _data = self.monitored_table.make_data([], 'Ingress.set_outgoing')
            try:
                self.ports_table.entry_add(self.dev_tgt, [_keys], [_data])
            except:
                pass

    def optimize_allocation(self, switches):
        pass

    def populate_monitored(self, entries):
        base_idx = 0
        dark_base_idx = 0
        for entry in entries:
            prefix, length = entry.split('/')
            mask = 2**(32 - int(length)) - 1
            _keys = self.monitored_table.make_key([gc.KeyTuple('meta.addr', prefix, None, int(length))])
            _data = self.monitored_table.make_data([
                gc.DataTuple('base_idx', base_idx),
                gc.DataTuple('mask', mask),
                gc.DataTuple('dark_base_idx', dark_base_idx)
            ], 'Ingress.calc_idx')
            try:
                self.monitored_table.entry_add(self.dev_tgt, [_keys], [_data])
            except:
                pass
            # save in local dictionary
            ipnet = ipaddress.IPv4Network(entry)
            netws = list(ipnet.subnets(new_prefix=32))
            self.index_prefix_mapping.extend(netws)

            for i in range(len(netws)):
                node = self.prefix_index_mapping.add(str(netws[i]))
                node.data['index'] = base_idx + i

            dark_netws = list(ipnet.subnets(new_prefix=24))
            for i in range(len(dark_netws)):
                dark_netw = '.'.join(str(dark_netws[i]).split('.')[:3])
                self.dark_prefix_index_mapping[dark_netw] = dark_base_idx + i            

            base_idx += len(netws)
            dark_base_idx += len(dark_netws)

    def add_mirroring(self, eg_ports, mc_session_id, log_session_id):
        mirror_table = self.bfrt_info.table_get('$mirror.cfg')
        pre_node_table = self.bfrt_info.table_get('$pre.node')
        pre_mgid_table = self.bfrt_info.table_get('$pre.mgid')
        rec_ports = [RECIRCULATE_PORT + 128*x for x in range(NUM_PIPES)]

        rid = 1
        # multicast nodes
        for port in eg_ports:
            for _ in range(3):
                l1_node_key = pre_node_table.make_key([gc.KeyTuple('$MULTICAST_NODE_ID', rid)])
                l2_node = pre_node_table.make_data([
                    gc.DataTuple('$MULTICAST_RID', rid),
                    gc.DataTuple('$DEV_PORT', int_arr_val=[port])
                ])
                rid += 1
                try:
                    pre_node_table.entry_add(self.dev_tgt, [l1_node_key], [l2_node])   
                except:
                    pass
        
        # multicast group
        mg_id_key = pre_mgid_table.make_key([gc.KeyTuple('$MGID', 1)])
        mg_id_data = pre_mgid_table.make_data([
            gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=list(range(1, rid))),
            gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID', bool_arr_val=[False]*(rid-1)),
            gc.DataTuple('$MULTICAST_NODE_L1_XID', int_arr_val=[0]*(rid-1)),
        ])
        try:
            pre_mgid_table.entry_add(self.dev_tgt, [mg_id_key], [mg_id_data])
        except:
            pass

        init_rid = rid
        # recirculation nodes
        for port in rec_ports:
            l1_node_key = pre_node_table.make_key([gc.KeyTuple('$MULTICAST_NODE_ID', rid)])
            l2_node = pre_node_table.make_data([
                gc.DataTuple('$MULTICAST_RID', rid),
                gc.DataTuple('$DEV_PORT', int_arr_val=[port])
            ])
            rid += 1
            try:
                pre_node_table.entry_add(self.dev_tgt, [l1_node_key], [l2_node])   
            except:
                pass
        
        # multicast group
        mg_id_key = pre_mgid_table.make_key([gc.KeyTuple('$MGID', 2)])
        mg_id_data = pre_mgid_table.make_data([
            gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=list(range(init_rid, rid))),
            gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID', bool_arr_val=[False]*(rid-init_rid)),
            gc.DataTuple('$MULTICAST_NODE_L1_XID', int_arr_val=[0]*(rid-init_rid)),
        ])
        try:
            pre_mgid_table.entry_add(self.dev_tgt, [mg_id_key], [mg_id_data])
        except:
            pass

        mirror_key  = mirror_table.make_key([gc.KeyTuple('$sid', mc_session_id)])
        mirror_data = mirror_table.make_data([
            gc.DataTuple('$direction', str_val="BOTH"),
            gc.DataTuple('$session_enable', bool_val=True),
            gc.DataTuple('$mcast_rid', 1),
            gc.DataTuple('$mcast_grp_a', 1),
            gc.DataTuple('$mcast_grp_a_valid', bool_val=True),
            gc.DataTuple('$mcast_grp_b', 2),
            gc.DataTuple('$mcast_grp_b_valid', bool_val=True),
            gc.DataTuple('$max_pkt_len', 39)
        ], "$normal")

        try:
            mirror_table.entry_add(self.dev_tgt, [mirror_key], [mirror_data])
        except:
            pass

        mirror_key  = mirror_table.make_key([gc.KeyTuple('$sid', log_session_id)])
        mirror_data = mirror_table.make_data([
            gc.DataTuple('$direction', str_val="BOTH"),
            gc.DataTuple('$session_enable', bool_val=True),
            gc.DataTuple('$ucast_egress_port', LOG_PORT),
            gc.DataTuple('$ucast_egress_port_valid', bool_val=True)
            ], "$normal")

        try:
            mirror_table.entry_add(self.dev_tgt, [mirror_key], [mirror_data])
        except:
            pass

    def get_gen_info(self):
        data = []
        for name in self.bfrt_info.table_dict.keys():
            if name.split('.')[0] == 'pipe':
                t = self.bfrt_info.table_get(name)
                table_name = t.info.name_get()
                if table_name != name:
                    continue
                table_type = t.info.type_get()
                try:
                    result = t.usage_get(self.dev_tgt)
                    table_usage = next(result)
                except:
                    table_usage = 'n/a'
                table_size = t.info.size_get()
                data.append([table_name, table_type, table_usage, table_size])
        headers = ['Full Table Name','Type','Usage','Capacity']
        return data, headers

    def read_register(self, table, index, flags={"from_hw": True}):
        _keys = table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])
        data, _ = next(table.entry_get(
            self.dev_tgt,
            [
                _keys
            ],
            flags=flags
        ))
        data_name = table.info.data_dict_allname["f1"]
        return data.to_dict()[data_name]

    def write_register(self, table, index, value, flags={"from_hw": True}):
        _keys = table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])
        data_name = table.info.data_dict_allname["f1"]
        _data = table.make_data([gc.DataTuple(data_name, value)])
        table.entry_add(self.dev_tgt, [_keys], [_data])

    def get_inactive_prefixes(self, covering_prefix=None):
        inactive_prefixes = []
        with self.lock:
            if covering_prefix is None:
                for i in range(len(self.index_prefix_mapping)):
                    if not self.counters[i]:
                        inactive_prefixes.append(str(self.index_prefix_mapping[i]))
            else:
                covered = self.prefix_index_mapping.search_covered(covering_prefix)
                for node in covered:
                    if not self.counters[node.data['index']]:
                        inactive_prefixes.append(str(node.prefix))
        
        return aggregate(inactive_prefixes)

    def run(self):
        while True:
            logging.info('Starting collecting values...')
            # collect global table(s)
            inactive_pfxs = dict()
            inactive_addr = 0
            for i in range(len(self.index_prefix_mapping)):
                active = 0
                t_val = self.read_register(self.flag_table, i)
                active |= int(any(t_val))
                with self.lock:
                    if active:
                        if not self.counters[i]:
                            self.write_register(self.global_table, i , 1)
                            logging.warning(f'Prefix {self.index_prefix_mapping[i]} became active.')
                        self.write_register(self.flag_table, i, 0)
                        self.counters[i] = self.alpha + 1
                    else:
                        if self.counters[i] > 1:
                            self.counters[i] -= 1
                        else:
                            inactive_addr += 1
                            pfx = ".".join(str(self.index_prefix_mapping[i]).split(".")[:3])
                            if pfx not in inactive_pfxs:
                                inactive_pfxs[pfx] = 0
                            inactive_pfxs[pfx] += 1

                            if self.counters[i] == 1:
                                self.write_register(self.global_table, i, 0)
                                self.counters[i] = 0

            # reset logging state
            for i in range(self.dark_table_size):
                num_pkts = self.read_register(self.dark_table, i)
                if sum(num_pkts) > THRESHOLD:
                    self.write_register(self.dark_table, i, 0)

            logging.info(f'Waiting for {self.time_interval} seconds...')
            time.sleep(self.time_interval)

'''

if __name__ == "__main__":
    print("Start Controller....")
    
    logging.basicConfig(level="DEBUG",
                        format="%(asctime)s|%(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    parser = argparse.ArgumentParser()
    parser.add_argument('--interval', default=3, type=int)
    parser.add_argument('--global-table-size', default=4194304, type=int)
    parser.add_argument('--dark-meter-size', default=16384, type=int)
    parser.add_argument('--max-packet-rate', default=1, type=int)
    parser.add_argument('--max-byte-rate', default=1, type=int)
    parser.add_argument('--avg-byte-rate', default=1, type=int)
    parser.add_argument('--avg-packet-rate', default=1, type=int)
    parser.add_argument('--alpha', default=1, type=int)
    parser.add_argument('-s', '--setup', default=True, type=bool)
    parser.add_argument('--monitored', default='../input_files/monitored.txt', type=str)
    parser.add_argument('--outgoing', nargs='*', default=[1], type=int)
    parser.add_argument('--incoming', nargs='*', default=[2], type=int)

    args = parser.parse_args()

    client = LocalClient(args.interval, args.global_table_size, args.dark_meter_size, args. alpha, args.monitored, {'incoming': args.incoming, 'outgoing': args.outgoing}, \
        args.max_packet_rate, args.max_byte_rate, args.avg_packet_rate, args.avg_byte_rate)
    client.get_gen_info()
    if args.setup:
        client.run()

'''