#!/usr/bin/env python
import sys
import socket
import time
import random
import struct
import dpkt.ip
import dpkt.icmp

# Probe using the fact GFW will send back TCP RST if keyword detected in HTTP GET URL or HOST
ERROR_NO_DATA = 11
PROBE_SPORT = 19840 + random.randint(1, 1000)
PROBE_DST = sys.argv[1]
PROBE_DPORT = int(sys.argv[2])

icmp_dump_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_dump_socket.settimeout(0)
tcp_dump_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_dump_socket.settimeout(0)

def main():
    for ttl in range(1, 15):
        probe(ttl)
        time.sleep(1)
        router_ip = dump_icmp_to_get_this_hop_router_ip()
        print('via: %s' % router_ip)
        found = dump_tcp_to_find_out_if_gfw_is_jamming()
        if found:
            print('found router attached GFW: %s' % router_ip)
            sys.exit(0)
    print('router attached GFW not found')
    sys.exit(1)


def dump_icmp_to_get_this_hop_router_ip():
    router_ip = None
    try:
        while True:
            icmp_packet = dpkt.ip.IP(icmp_dump_socket.recv(1024))
            if dpkt.icmp.ICMP_TIMEXCEED == icmp_packet.icmp.type and\
               dpkt.icmp.ICMP_TIMEXCEED_INTRANS == icmp_packet.icmp.code and\
               PROBE_DST == socket.inet_ntoa(icmp_packet.icmp.data.data.dst):
                router_ip = socket.inet_ntoa(icmp_packet.src)
    except socket.error as e:
        if ERROR_NO_DATA == e[0]:
            pass
        else:
            raise
    return router_ip


def dump_tcp_to_find_out_if_gfw_is_jamming():
    ttl_observed = set()
    try:
        while True:
            tcp_packet = dpkt.ip.IP(tcp_dump_socket.recv(1024))
            if PROBE_DST == socket.inet_ntoa(tcp_packet.src) and PROBE_DPORT == tcp_packet.tcp.sport:
                ttl_observed.add(tcp_packet.ttl)
    except socket.error as e:
        if ERROR_NO_DATA == e[0]:
            pass
        else:
            raise
    if len(ttl_observed) > 1:
        return True
    return False


def probe(ttl):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.settimeout(5)
        tcp_socket.bind(('', PROBE_SPORT))
        tcp_socket.connect((PROBE_DST, PROBE_DPORT))
        tcp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        tcp_socket.send('GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n')
    finally:
        l_onoff = 1
        l_linger = 0
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
        tcp_socket.close()

main()

