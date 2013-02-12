#!/usr/bin/env python
import socket
import os
import sys
import time
from scapy.layers.inet import IP, TCP, IPerror, TCPerror

MONGOL_SYS_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if MONGOL_SYS_PATH not in sys.path:
    sys.path.append(MONGOL_SYS_PATH)
import networking

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

def main(dst, sport, ttl):
    iface, src, _ = networking.get_route(dst)
    sniffer = networking.create_sniffer(iface, src, dst)
    probe = TcpPacketDropProbe(src, int(sport), dst, 80, int(ttl), sniffer)
    sniffer.start_sniffing()
    probe.poke()
    time.sleep(2)
    sniffer.stop_sniffing()
    report = probe.peek()
    packets = report.pop('PACKETS')
    print(report)
    for mark, packet in packets:
        formatted_packet = packet.sprintf('%.time% %IP.src% -> %IP.dst% %TCP.flags%')
        print('[%s] %s' % (mark, formatted_packet))


class TcpPacketDropProbe(object):
    def __init__(self, src, sport, dst, dport, ttl, sniffer):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.ttl = ttl
        self.sniffer = sniffer
        self.report = {
            'ROUTER_IP_FOUND_BY_PACKET_1': None,
            'ROUTER_IP_FOUND_BY_PACKET_2': None,
            'ROUTER_IP_FOUND_BY_PACKET_3': None,
            'PACKETS': []
        }

    def poke(self):
        syn1 = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 1, ttl=self.ttl) / TCP(
            sport=self.sport, dport=self.dport, flags='S', seq=0)
        networking.send(syn1)
        self.report['PACKETS'].append(('PACKET_1', syn1))
        syn2 = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 2, ttl=self.ttl) / TCP(
            sport=self.sport, dport=self.dport, flags='S', seq=0)
        networking.send(syn2)
        self.report['PACKETS'].append(('PACKET_2', syn2))
        syn3 = IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 3, ttl=self.ttl) / TCP(
            sport=self.sport, dport=self.dport, flags='S', seq=0)
        networking.send(syn3)
        self.report['PACKETS'].append(('PACKET_3', syn3))

    def peek(self):
        for packet in self.sniffer.packets:
            if TCP in packet:
                self.analyze_tcp_packet(packet)
            elif IPerror in packet and TCPerror in packet:
                self.analyze_tcp_error_packet(packet)
        return self.report

    def analyze_tcp_packet(self, packet):
        if self.dport != packet[TCP].sport:
            return
        if self.sport != packet[TCP].dport:
            return
        self.report['PACKETS'].append(('UNKNOWN', packet))

    def analyze_tcp_error_packet(self, packet):
        if self.sport != packet[TCPerror].sport:
            return
        if self.dport != packet[TCPerror].dport:
            return
        if self.ttl * 10 + 1 == packet[IPerror].id:
            self.record_router_ip(packet.src, 1, packet)
        elif self.ttl * 10 + 2 == packet[IPerror].id:
            self.record_router_ip(packet.src, 2, packet)
        elif self.ttl * 10 + 3 == packet[IPerror].id:
            self.record_router_ip(packet.src, 3, packet)
        else:
            self.report['PACKETS'].append(('UNKNOWN', packet))

    def record_router_ip(self, router_ip, packet_index, packet):
        if self.report['ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index]:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index, packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index, packet))
            self.report['ROUTER_IP_FOUND_BY_PACKET_%s' % packet_index] = router_ip

if 1 == len(sys.argv):
    print('[Usage] ./tcp_packet_drop.py destination_ip sport ttl')
    sys.exit(3)
else:
    main(*sys.argv[1:])