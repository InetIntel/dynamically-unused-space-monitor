#!/usr/bin/python
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