import netifaces as ni
import json
import socket
import threading
import requests
import os
from flask import Flask, jsonify, request, Response, abort
from flask_cors import CORS
from controllertof import LocalClient
import logging
from werkzeug.exceptions import HTTPException
import time
from argparse import ArgumentParser
from socket import getaddrinfo, gaierror, AF_INET, AF_INET6, SOCK_RAW, AI_NUMERICHOST

app = Flask(__name__)
CORS(app)

# check if IPv4 prefix
def check_prefix(prefix):
    try:
        prefix = request.args.get('prefix').strip()
        pfx_network, pfx_len = prefix.split('/')[0], int(prefix.split('/')[1])
    except:
        return False
    try:
        family, _, _, _, _ = getaddrinfo(pfx_network, None, 0, SOCK_RAW, 6, AI_NUMERICHOST)[0]
    except gaierror:
        return False

    if family == AF_INET:
        if not (0 <= pfx_len <= 32):
            return False
    elif family == AF_INET6:
        return False
        # if not (0 <= pfx_len <= 128):
        #    return False
    else:
        # shouldn't enter this
        return False
    return True

@app.route('/')
def hello():
    return 'Hi, I am alive!'

# return inactive prefixes
@app.route('/inactive', methods=['GET'])
def getInactivePrefixes():
    prefix = request.args.get('prefix')
    if prefix is not None and not check_prefix(prefix):
        return Response(status=400)
    inactive_prefixes_list = controller.get_inactive_prefixes(prefix)
    return jsonify(inactive_prefixes=inactive_prefixes_list), 200

@app.route('/info', methods=['GET'])
def getInfo():
    info, headers = controller.get_gen_info()
    return jsonify(info=info, headers=headers), 200

@app.errorhandler(HTTPException)
def handle_exception(e):
    response = e.get_response()
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response

if __name__ == '__main__':
    logging.basicConfig(level="DEBUG",
                        format="%(asctime)s|%(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    parser = ArgumentParser()
    parser.add_argument('--interval', default=3, type=int)
    parser.add_argument('--global-table-size', default=4194304, type=int)
    parser.add_argument('--dark-table-size', default=1024, type=int)
    parser.add_argument('--alpha', default=1, type=int)
    parser.add_argument('--monitored', default='../input_files/monitored.txt', type=str)
    parser.add_argument('--outgoing', action='append', default=[1], type=int)
    parser.add_argument('--incoming', action='append', default=[2], type=int)

    args = parser.parse_args()

    host_name = socket.gethostname()
    host_ip = socket.gethostbyname(host_name)
    port = 2002

    controller = LocalClient(args.interval, args.global_table_size, args.dark_table_size, args. alpha, args.monitored, {'incoming': args.incoming, 'outgoing': args.outgoing})
    # run iterations in the background
    thread = threading.Thread(target=controller.run, name='periodic checks')
    thread.start()

    app.run(host=host_ip, port=port, threaded=True)