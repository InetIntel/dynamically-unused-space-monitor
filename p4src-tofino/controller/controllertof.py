#!/usr/bin/python3

import os
import sys
import pdb
import logging

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

import bfrt_grpc.client as gc
from tabulate import tabulate
import argparse, time, ipaddress
from aggregate6 import aggregate
from radix import Radix
import threading

class LocalClient:
    def __init__(self, time_interval, global_table_size, dark_table_size, alpha, monitored_path, ports):
        self.time_interval = time_interval*60 # convert to sec
        self.global_table_size = global_table_size
        self.dark_table_size = dark_table_size
        self.alpha = alpha
        self.counters = [self.alpha]*self.global_table_size
        self.monitored_path = monitored_path
        self.index_prefix_mapping = []
        self.prefix_index_mapping = Radix()
        self.ports = ports
        self.lock = threading.Lock()
        self._setup()

    def parse_monitored(self, path):
        monitored_prefixes = []
        with open(path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                monitored_prefixes.append(line)
        return monitored_prefixes

    def _setup(self):
        bfrt_client_id = 0

        self.interface = gc.ClientInterface(
            grpc_addr = 'localhost:50052',
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
        self.dark_table = self.bfrt_info.table_get('pipe.Ingress.dark_table')
        self.interface.bind_pipeline_config(self.bfrt_info.p4_name_get())
    # def _setup_tables(self):
        self.add_mirroring([5, 5, 6], 1, 2)  # set up mirroring
        monitored_prefixes = self.parse_monitored(self.monitored_path)   # populate monitored table
        self.populate_monitored(monitored_prefixes)
        self.add_ports(self.ports)
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
        for entry in entries:
            prefix, length = entry.split('/')
            mask = 2**(32 - int(length)) - 1
            _keys = self.monitored_table.make_key([gc.KeyTuple('meta.addr', prefix, None, int(length))])
            _data = self.monitored_table.make_data([
                gc.DataTuple('base_idx', base_idx),
                gc.DataTuple('mask', mask)
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

            base_idx += len(netws)

    def add_mirroring(self, eg_ports, mc_session_id, log_session_id):
        mirror_table = self.bfrt_info.table_get('$mirror.cfg')
        pre_node_table = self.bfrt_info.table_get('$pre.node')
        pre_mgid_table = self.bfrt_info.table_get('$pre.mgid')

        rid = 1
        # multicast nodes
        for port in eg_ports:
            for i in range(3):
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

        mirror_key  = mirror_table.make_key([gc.KeyTuple('$sid', mc_session_id)])
        mirror_data = mirror_table.make_data([
            gc.DataTuple('$direction', str_val="BOTH"),
            gc.DataTuple('$session_enable', bool_val=True),
            gc.DataTuple('$mcast_grp_a', 1),
            gc.DataTuple('$mcast_grp_a_valid', bool_val=True),
            gc.DataTuple('$mcast_rid', 1),
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
        pipe = 0
        while True:
            logging.info('Starting collecting values...')
            # collect global table(s)
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
                        if self.counters[i] == 1:
                            self.write_register(self.global_table, i, 0)
                            self.counters[i] = 0
                        elif self.counters[i] > 1:
                            self.counters[i] -= 1

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
    parser.add_argument('--dark-table-size', default=1024, type=int)
    parser.add_argument('--alpha', default=1, type=int)
    parser.add_argument('-s', '--setup', default=True, type=bool)
    parser.add_argument('--monitored', default='../input_files/monitored.txt', type=str)
    parser.add_argument('--outgoing', action='append', default=[1], type=int)
    parser.add_argument('--incoming', action='append', default=[2], type=int)

    args = parser.parse_args()

    client = LocalClient(args.interval, args.global_table_size, args.dark_table_size, args. alpha, args.monitored, {'incoming': args.incoming, 'outgoing': args.outgoing})
    client.get_gen_info()
    if args.setup:
        client.run()

'''