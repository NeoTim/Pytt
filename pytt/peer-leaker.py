#!/usr/bin/python

import requests
import sys
import re


def leak_peer(ip, port):
    url = "http://localhost:8080/fake"

    data = {"remote_ip": ip, "remote_port": port}

    s = requests.Session()

    s.get(url, params=data)

with open(sys.argv[1], "rb") as f:
    for line in f:
        r = re.search("handshake_manager_port->(.+?):\ ", line)
        if r:
            peer = r.groups(1)[0]
            if peer.startswith("127"):
                continue
            ip, port = peer.split(":")
            leak_peer(ip, port)
