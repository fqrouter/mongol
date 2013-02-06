#!/usr/bin/env python
import socket
import dpkt.ip
import dpkt.dns
import sys
import time

# Probe using the fact GFW will send back fake dns answer if the dns question is about certain domain name
#
# Send offending payload (A.K.A try resolve domain name twitter.com) with TTL 1
# PROBE =OFFENDING_PAYLOAD=> ROUTER-1 (TTL is 1)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1
# Router will send back a ICMP packet tell us its (the router) ip address
#
# Send offending payload (A.K.A try resolve domain name twitter.com) with big enough TTL
# PROBE =OFFENDING_PAYLOAD => ROUTER-1 .. => ROUTER ATTACHED GFW (TTL is N)
# PROBE <=ICMP_TTL_EXCEEDED= ROUTER-1 .. <= ROUTER ATTACHED GFW
# PROBE <=FAKE_DNS_ANSWER= ROUTER-1 .. <=ROUTER ATTACHED GFW (FAKE_DNS_ANSWER was sent by GFW)
# The wrong dns answer sent back by GFW will be accepted by our browser so will try to access twitter.com
# via a wrong ip address. To tell if the answer is right or wrong, check the list below.
# When we found a wrong answer, we know the router is attached with GFW. The ip adress of the router
# can be told from the ICMP packet sent back previously.

# source http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
WRONG_ANSWERS = {
    '4.36.66.178',
    '8.7.198.45',
    '37.61.54.158',
    '46.82.174.68',
    '59.24.3.173',
    '64.33.88.161',
    '64.33.99.47',
    '64.66.163.251',
    '65.104.202.252',
    '65.160.219.113',
    '66.45.252.237',
    '72.14.205.99',
    '72.14.205.104',
    '78.16.49.15',
    '93.46.8.89',
    '128.121.126.139',
    '159.106.121.75',
    '169.132.13.103',
    '192.67.198.6',
    '202.106.1.2',
    '202.181.7.85',
    '203.161.230.171',
    '207.12.88.98',
    '208.56.31.43',
    '209.36.73.33',
    '209.145.54.50',
    '209.220.30.174',
    '211.94.66.147',
    '213.169.251.35',
    '216.221.188.182',
    '216.234.179.13'
}
ERROR_NO_DATA = 11
PROBE_DST = None # set via command line
PROBE_DPORT = 53 # GFW only jam DNS at port 53

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
udp_socket.settimeout(0)
icmp_dump_socket = sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_dump_socket.settimeout(0)
OFFENDING_PAYLOAD = str(dpkt.dns.DNS(qd=[dpkt.dns.DNS.Q(name='twitter.com')]))

def main(dst, start_ttl=1, end_ttl=14, sport=0):
    global PROBE_DST
    PROBE_DST = dst
    udp_socket.bind(('', int(sport))) # if sport change the route going through might change
    for ttl in range(int(start_ttl), int(end_ttl) + 1):
        send_offending_payload(ttl)
        time.sleep(1)
        router_ip = dump_icmp_to_get_this_hop_router_ip()
        print('[%s] via: %s' % (ttl, router_ip or '*'))
        fake_answer = dump_udp_to_find_out_fake_answer_sent_by_gfw()
        if fake_answer:
            print('found router attached GFW: %s which resolves twitter.com to %s' % (router_ip, fake_answer))
            sys.exit(0)
    print('router attached GFW not found')
    sys.exit(1)


def send_offending_payload(ttl):
    udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    udp_socket.sendto(OFFENDING_PAYLOAD, (PROBE_DST, 53))


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


def dump_udp_to_find_out_fake_answer_sent_by_gfw():
    try:
        while True:
            dns_packet = dpkt.dns.DNS(udp_socket.recv(1024))
            if dns_packet.an:
                answer = socket.inet_ntoa(dns_packet.an[0].rdata)
                if answer in WRONG_ANSWERS:
                    return answer
            else:
                return '[BLANK]'
    except socket.error as e:
        if ERROR_NO_DATA == e[0]:
            pass # all packets dumped, move on
        else:
            raise
    return None


if 1 == len(sys.argv):
    print('[Usage] ./fake_dns_answer.py destination_ip [start_ttl] [end_ttl]')
    sys.exit(3)
else:
    main(*sys.argv[1:])