#!/usr/bin/env python
import sys
import socket
import time
import random
import struct
import dpkt.ip
import dpkt.icmp

# Probe using the fact GFW will send back TCP RST if keyword detected in HTTP GET URL or HOST
#
# Three way handshake complete in normal way
# PROBE =SYN=> ROUTER-1 => .. => ROUTER-N => DESTINATION (Normal TTL)
# PROBE <=SYN+ACK= ROUTER-1 <= .. <= ROUTER-N <= DESTINATION
# PROBE =ACK=> ROUTER-1 => .. => ROUTER-N => DESTINATION (Normal TTL)
# GFW will not jam the connection, unless there was offending payload found previously,
# which means it is in unconditional mode.
# Full three way handshake is unnecessary to trigger TCP RST, without SYN+ACK also works.
# However because we can not use raw socket to send arbitrary ip packet, so we have to
# complete the handshake to send the following offending payload.
# Also, if you are using wireless router (or any NAT router), without SYN+ACK sent back from the destination
# the following packet send out will be blocked by your wireless router (or any NAT router)
#
# Send offending payload (A.K.A GET facebook.com) with TTL 1
# PROBE =OFFENDING_PAYLOAD=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send offending payload (A.K.A GET facebook.com) with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# PROBE <=RST= ROUTER-1 .. <=ROUTER ATTACHED GFW (RST was sent by GFW to jam the connection)
# The RST sent back from GFW will have TTL different from other packets sent back from destination.
# So by checking TTL of returning packets we can tell if GFW is jamming the connection.
# Also based on the ICMP packet we can tell the ip address of router attached GFW.

ERROR_NO_DATA = 11
OFFENDING_PAYLOAD = 'GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n'

PROBE_DST = None # set via command line
PROBE_DPORT = None # set via command line
PROBE_SPORT = None # set via command line

icmp_dump_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_dump_socket.settimeout(0)
tcp_dump_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_dump_socket.settimeout(0)

def main(dst, dport=80, start_ttl=1, end_ttl=14, sport=19840 + random.randint(1, 1000)):
    global PROBE_DST
    global PROBE_DPORT
    global PROBE_SPORT
    PROBE_DST = dst
    PROBE_DPORT = int(dport)
    PROBE_SPORT = int(sport)
    for ttl in range(int(start_ttl), int(end_ttl) + 1):
        connect_and_send_offending_payload(ttl)
        time.sleep(1)
        router_ip = dump_icmp_to_get_this_hop_router_ip()
        print('[%s] via: %s' % (ttl, router_ip or '*'))
        found = dump_tcp_to_find_out_if_gfw_is_jamming()
        if found:
            if ttl < 3:
                print('GFW is in unconditional mode for the destination, try another destination')
                sys.exit(2)
            print('found router attached GFW: %s' % router_ip)
            sys.exit(0)
    print('router attached GFW not found')
    sys.exit(1)


def connect_and_send_offending_payload(ttl):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.settimeout(5)
        tcp_socket.bind(('', PROBE_SPORT)) # if sport change the route going through might change
        tcp_socket.connect((PROBE_DST, PROBE_DPORT))
        tcp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        tcp_socket.send(OFFENDING_PAYLOAD)
    finally:
        immediately_close_tcp_socket_so_sport_can_be_reused(tcp_socket)


def immediately_close_tcp_socket_so_sport_can_be_reused(tcp_socket):
    l_onoff = 1
    l_linger = 0
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
    tcp_socket.close()


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
            pass # all packets dumped, move on
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
            pass # all packets dumped, move on
        else:
            raise
    if len(ttl_observed) > 1:
        return True
    return False


if 1 == len(sys.argv):
    print('[Usage] ./tcp_rst.py destination_ip [destination_port] [start_ttl] [end_ttl] [probe_source_port]')
    sys.exit(3)
else:
    main(*sys.argv[1:])

