#!/usr/bin/env python
import socket
import dpkt.ip
import dpkt.tcp
import dpkt.icmp
import sys
import struct
import random
import time

# Probe using the fact GFW will configure some router to only drop packet of certain source ip and port combination
#
# Normally GFW does not drop your packet, it will jam the connection using TCP RST or FAKE DNS ANSWER.
# However, if you are running some OpenVPN like service on the server and being detected *somehow* by GFW,
# it will block your ip or just a specific port of that ip. We can use the fact some router is dropping packet
# to show its connection with GFW.
#
# Send offending payload (A.K.A source port being the blocked port) with TTL 1
# PROBE =OFFENDING_PAYLOAD=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send offending payload (A.K.A source port being the blocked port) with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=NOTHING= (Nothing returned after 2 seconds)
# We know the router is dropping our packet as no ICMP being returned
#
# Send non-offending payload (A.K.A source port being the reference port) with big enough TTL
# PROBE =NON_OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# Although the router ip returned from this ICMP might not be same router, as source port was not the same.
# But there is a great chance the router is the same router, as we can tell same router is responsible for
# TCP RST and FAKE DNS ANSWER.

ERROR_NO_DATA = 11

PROBE_DST = None # set via command line
PROBE_DPORT = 80

icmp_dump_socket = sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_dump_socket.settimeout(0)

def main(dst, blocked_sport, tcp_or_udp='tcp',
         reference_sport=19840 + random.randint(1, 1000),
         start_ttl=4, end_ttl=14):
    global PROBE_DST
    PROBE_DST = dst
    blocked_sport = int(blocked_sport)
    reference_sport = int(reference_sport)
    last_seen_router_ip = None
    count_of_packet_loss_in_a_row = 0
    for ttl in range(int(start_ttl), int(end_ttl) + 1):
        if 'tcp' == tcp_or_udp:
            send_tcp_packet(blocked_sport, ttl)
            send_tcp_packet(reference_sport, ttl)
            send_tcp_packet(blocked_sport, ttl) # send syn twice to ensure the packet loss was not a accident
        else:
            assert 'udp' == tcp_or_udp
            send_udp_packet(blocked_sport, ttl)
            send_udp_packet(reference_sport, ttl)
            send_udp_packet(blocked_sport, ttl) # send syn twice to ensure the packet loss was not a accident
        time.sleep(2)
        routers_ip = dump_icmp_to_get_this_hop_routers_ip()
        print('[%2s] via: %15s %15s' %
              (ttl, routers_ip.get(blocked_sport) or '*', routers_ip.get(reference_sport) or '*'))
        if blocked_sport in routers_ip:
            last_seen_router_ip = routers_ip[blocked_sport]
            count_of_packet_loss_in_a_row = 0
        elif reference_sport in routers_ip:
            count_of_packet_loss_in_a_row += 1
        if count_of_packet_loss_in_a_row == 2:
            print('packet dropped at router: %s' % last_seen_router_ip)
            sys.exit(0)
    print('packet not being dropped')
    sys.exit(1)


def send_tcp_packet(sport, ttl):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        tcp_socket.settimeout(0)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind(('', sport))
        tcp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        tcp_socket.connect((PROBE_DST, PROBE_DPORT))
    except socket.error as e:
        pass
    finally:
        immediately_close_tcp_socket_so_sport_can_be_reused(tcp_socket)


def immediately_close_tcp_socket_so_sport_can_be_reused(tcp_socket):
    l_onoff = 1
    l_linger = 0
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
    tcp_socket.close()


def send_udp_packet(sport, ttl):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        udp_socket.settimeout(0)
        udp_socket.bind(('', sport))
        udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        udp_socket.sendto('blahblahblah', (PROBE_DST, PROBE_DPORT))
    finally:
        udp_socket.close()


def dump_icmp_to_get_this_hop_routers_ip():
    routers_ip = {}
    try:
        while True:
            icmp_packet = dpkt.ip.IP(icmp_dump_socket.recv(1024))
            ttl_exceeded_packet = icmp_packet.icmp.data.ip
            if dpkt.icmp.ICMP_TIMEXCEED == icmp_packet.icmp.type and\
               dpkt.icmp.ICMP_TIMEXCEED_INTRANS == icmp_packet.icmp.code and\
               PROBE_DST == socket.inet_ntoa(ttl_exceeded_packet.dst):
                sport, dport = struct.unpack('>HH', str(ttl_exceeded_packet.data)[:4])
                assert PROBE_DPORT == dport
                router_ip = socket.inet_ntoa(icmp_packet.src)
                routers_ip[sport] = router_ip
    except socket.error as e:
        if ERROR_NO_DATA == e[0]:
            pass # all packets dumped, move on
        else:
            raise
    return routers_ip


if 1 == len(sys.argv):
    print('[Usage] ./packet_drop.py destination_ip blocked_source_port [reference_source_port]')
    sys.exit(3)
else:
    main(*sys.argv[1:])