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

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import argparse
from radix import Radix
import threading
import time
import ipaddress
from aggregate6 import aggregate
import logging

logging.basicConfig(level="DEBUG",
                        format="%(asctime)s|%(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
LOG_PORT = 6
THRESHOLD = 1024


class LocalClient:
    def __init__(self, time_interval, global_table_size, dark_table_size, alpha, monitored_path, ports):
        self.time_interval = time_interval*60
        self.global_table_size = global_table_size
        self.dark_table_size = dark_table_size
        self.alpha = alpha
        self.counters = [self.alpha]*self.global_table_size
        self.monitored_path = monitored_path
        self.index_prefix_mapping = []
        self.prefix_index_mapping = Radix()
        self.ports = ports
        self.controllers = dict()
        self.lock = threading.Lock()
        self.topo = None
        self._setup()

    def _setup(self):
        self.topo = load_topo('topology.json')
        # load controllers for all switches
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

        # set initial values of registers
        for sw, controller in self.controllers.items():
            print("Setting registers for switch {}".format(sw))
            for register in controller.get_register_arrays():
                if register == 'MyIngress.global_table':
                    controller.register_write(register, [0, self.global_table_size - 1], 1)
                else:
                    controller.register_reset(register)
        self.add_mirroring(100, 200)
        monitored_prefixes = self._read_monitored_prefixes(self.monitored_path)
        self.populate_monitored(monitored_prefixes)
        self.add_ports(self.ports)

    def add_ports(self, ports):
        for port in ports['incoming']:
            for controller in self.controllers.values():
                controller.table_add('MyIngress.ports', 'set_incoming', [str(port)], [])
        for port in ports['outgoing']:
            for controller in self.controllers.values():
                controller.table_add('MyIngress.ports', 'set_outgoing', [str(port)], [])

    def populate_monitored(self, entries):
        base_idx = 0
        for entry in entries:
            length = entry.split('/')[-1]
            for controller in self.controllers.values():
                controller.table_add('MyIngress.monitored', 'calc_idx', [entry], action_params=[str(base_idx), length])
            # save in local dictionary
            ipnet = ipaddress.IPv4Network(entry)
            netws = list(ipnet.subnets(new_prefix=32))
            self.index_prefix_mapping.extend(netws)

            for i in range(len(netws)):
                node = self.prefix_index_mapping.add(str(netws[i]))
                node.data['index'] = base_idx + i

            base_idx += len(netws)

    def _read_monitored_prefixes(self, path):
        monitored_prefixes = []
        with open(path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                monitored_prefixes.append(line)
        return monitored_prefixes

    def add_mirroring(self, mc_session_id, log_session_id):
        mc_grp_id = 1
        for sw, controller in self.controllers.items():
            rid = 1
            controller.mc_mgrp_create(mc_grp_id)
            for sw1 in self.controllers:
                if sw == sw1:
                    continue
                s_ip_addr, s_mac_addr = self.topo.node_to_node_interface_ip(sw1, sw), self.topo.node_to_node_mac(sw1, sw)
                for i in range(3):
                    handle = controller.mc_node_create(rid, [self.topo.node_to_node_port_num(sw, sw1)])
                    controller.mc_node_associate(mc_grp_id, handle)
                    controller.table_add("mcast_routers", "set_nhop_r", [str(rid)], [str(s_mac_addr), str(s_ip_addr)])
                    rid += 1
            controller.mirroring_add_mc(mc_session_id, mc_grp_id)
            controller.mirroring_add(log_session_id, LOG_PORT)
     
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
            for controller in self.controllers.values():
                t_val = controller.register_read('MyIngress.flag_table', i)
                active |= t_val
            with self.lock:
                if active:
                    for controller in self.controllers.values():
                        if not self.counters[i]:
                            controller.register_write('MyIngress.global_table', i , 1)
                        controller.register_write('MyIngress.flag_table', i, 0)
                    logging.warning(f'Prefix {self.index_prefix_mapping[i]} became active.')
                    self.counters[i] = self.alpha + 1
                else:
                    if self.counters[i] == 1:
                        for controller in self.controllers.values():
                            controller.register_write('MyIngress.global_table', i, 0)
                        self.counters[i] = 0
                    elif self.counters[i] > 1:
                        self.counters[i] -= 1

        # reset logging state
        for i in range(self.dark_table_size):
            for controller in self.controllers.values():
                num_pkts = controller.register_read('MyIngress.dark_table', i, 0)
                if num_pkts > THRESHOLD:
                    controller.register_write('MyIngress.dark_table', i, 0)

        logging.info(f'Waiting for {self.alpha} mins...')
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
    if args.setup:
        client.run()

'''