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

import cmd
import json
import socket
import time
import requests
import netifaces as ni
from tabulate import tabulate


class CLI(cmd.Cmd):
    prompt = 'darknet-detection>>'
    doc_header = 'Available commands:'

    def __init__(self, node_port=2002):
        super(CLI, self).__init__()
        self.port = node_port
        self.addr = socket.gethostbyname(socket.gethostname())
        #self.addr = ni.ifaddresses('eth1')[ni.AF_INET][0]['addr']

    def preloop(self):
        self.do_help('')

    def do_info(self, line):
        """info
        Show general info of P4 program."""
        res = requests.get(f'http://{self.addr}:{self.port}/info')
        headers, info = res.json().values()
        print(tabulate(info, headers=headers))

    def do_inactive(self, line):
        """inactive [<prefix>]
        See inactive prefixes within prefix <prefix>."""
        request_url = f'http://{self.addr}:{self.port}/inactive'
        if line:
            prefix = line.strip()
            request_url += f'?prefix={prefix}'
        info = requests.get(request_url)
        res_j = info.json()['inactive_prefixes']
        print('------Inactive Prefixes------')
        for x in res_j:
            print(x)
        print('-----------------------------')

    def do_bye(self, line):
        """bye
        Exit client."""
        return True


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=2002, type=int, help='Your port.')
    args = parser.parse_args()
    port = args.port
    CLI(port).cmdloop('Darknet detection client! Check your inactive prefixes.')