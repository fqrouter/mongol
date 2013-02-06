#!/usr/bin/env python
import sys
import socket
import time
import random
import dpkt.ip
import dpkt.icmp

# Probe using the fact GFW will send back TCP RST if keyword detected in HTTP GET URL or HOST
#
# Send SYN with TTL 1
# PROBE =SYN=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send offending payload after SYN (A.K.A GET facebook.com) with TTL 1
# PROBE =OFFENDING_PAYLOAD=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send SYN with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# SYN just by itself does not trigger GFW
#
# Send offending payload after SYN (A.K.A GET facebook.com) with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# PROBE <=RST= ROUTER-1 .. <=ROUTER ATTACHED GFW (RST was sent by GFW to jam the connection)
# SYN by itself does not trigger GFW. Offending payload by itself does not trigger GFW as well.
# Only if SYN follows the ACK in a short time, and keyword in the HTTP GET URL or HOST will trigger.
# SYN+ACK will not be sent back in this case, as SYN never reaches the destination.
# The RST sent back from GFW will have TTL different from other packets sent back from destination.
# So by checking TTL of returning packets we can tell if GFW is jamming the connection.
# Also based on the ICMP packet we can tell the ip address of router attached GFW.

def find_probe_src():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('123.125.114.144', 80))
        return s.getsockname()[0]
    finally:
        s.close()

ERROR_NO_DATA = 11
PROBE_DST = None # set via command line
PROBE_DPORT = None # set via command line
PROBE_SRC = find_probe_src()
PROBE_SPORT = None # set via command line

icmp_dump_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_dump_socket.settimeout(0)
tcp_dump_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_dump_socket.settimeout(0)
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

def main(dst, dport=80, start_ttl=4, end_ttl=14, sport=19840 + random.randint(1, 1000)):
    global PROBE_DST
    global PROBE_DPORT
    global PROBE_SPORT
    PROBE_DST = dst
    PROBE_DPORT = int(dport)
    PROBE_SPORT = int(sport)
    for ttl in range(int(start_ttl), int(end_ttl) + 1):
        send_syn(ttl)
        send_offending_payload(ttl)
        time.sleep(1)
        router_ip = dump_icmp_to_get_this_hop_router_ip()
        print('[%s] via: %s' % (ttl, router_ip or '*'))
        found = dump_tcp_to_find_out_if_gfw_is_jamming()
        if found:
            if ttl == start_ttl:
                print('GFW is in unconditional mode for the destination, try another destination')
                sys.exit(2)
            print('found router attached GFW: %s' % router_ip)
            sys.exit(0)
    print('router attached GFW not found')
    sys.exit(1)


def send_syn(ttl):
    SYN = dpkt.ip.IP(
        p=dpkt.ip.IP_PROTO_TCP, src=socket.inet_aton(PROBE_SRC), dst=socket.inet_aton(PROBE_DST),
        id=ttl * 10 + 1, ttl=ttl,
        data=dpkt.tcp.TCP(
            sport=PROBE_SPORT, dport=PROBE_DPORT, flags=dpkt.tcp.TH_SYN, seq=0
        )
    )
    raw_socket.sendto(str(SYN), (PROBE_DST, PROBE_DPORT))


def send_offending_payload(ttl):
    OFFENDING_PAYLOAD = dpkt.ip.IP(
        p=dpkt.ip.IP_PROTO_TCP, src=socket.inet_aton(PROBE_SRC), dst=socket.inet_aton(PROBE_DST),
        id=ttl * 10 + 2, ttl=ttl,
        data=dpkt.tcp.TCP(
            sport=PROBE_SPORT, dport=PROBE_DPORT, flags=dpkt.tcp.TH_ACK, seq=1, ack=100,
            data='GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n'
        )
    )
    raw_socket.sendto(str(OFFENDING_PAYLOAD), (PROBE_DST, PROBE_DPORT))


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