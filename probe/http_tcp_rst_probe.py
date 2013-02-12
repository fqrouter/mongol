#!/usr/bin/env python
import sys
import time
import os
from scapy.layers.inet import IP, TCP, IPerror, TCPerror
from scapy.packet import Raw

MONGOL_SYS_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if MONGOL_SYS_PATH not in sys.path:
    sys.path.append(MONGOL_SYS_PATH)
import networking

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

TH_SYN = 0x02        # synchronize sequence numbers
TH_RST = 0x04        # reset connection
TH_ACK = 0x10        # acknowledgment number set
SPORT = 19840
DPORT = 80

def main(dst, ttl):
    iface, src, _ = networking.get_route(dst)
    sniffer = networking.create_sniffer(iface, src, dst)
    probe = HttpTcpRstProbe(src, SPORT, dst, DPORT, int(ttl), sniffer)
    sniffer.start_sniffing()
    probe.poke()
    time.sleep(2)
    sniffer.stop_sniffing()
    report = probe.peek()
    report.pop('PACKETS')
    print(report)


class HttpTcpRstProbe(object):
    def __init__(self, src, sport, dst, dport, ttl, sniffer):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.ttl = ttl
        self.sniffer = sniffer
        self.report = {
            'ROUTER_IP_FOUND_BY_SYN': None,
            'ROUTER_IP_FOUND_BY_HTTP_GET': None,
            'SYN_ACK?': None,
            'RST_AFTER_SYN?': None,
            'RST_AFTER_HTTP_GET?': None,
            'PACKETS': []
        }


    def poke(self):
        networking.send(IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 1, ttl=self.ttl) / TCP(
            sport=self.sport, dport=self.dport, flags='S', seq=0))
        time.sleep(2)
        self.http_get_sent_at = time.time()
        networking.send(IP(src=self.src, dst=self.dst, id=self.ttl * 10 + 2, ttl=self.ttl) / TCP(
            sport=self.sport, dport=self.dport, flags='A', seq=1, ack=100) / Raw(
            'GET / HTTP/1.1\r\nHost: www.facebook.com\r\n\r\n'))

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
        packet.show2()
        if packet[TCP].flags & TH_SYN and packet[TCP].flags & TH_ACK:
            self.record_syn_ack(packet)
        elif packet[TCP].flags & TH_RST:
            if packet.time < self.http_get_sent_at:
                self.record_rst_after_syn(packet)
            else:
                self.record_rst_after_http_get(packet)
        else:
            self.report['PACKETS'].append(('UNKNOWN', packet))

    def analyze_tcp_error_packet(self, packet):
        if self.sport != packet[TCPerror].sport:
            return
        if self.dport != packet[TCPerror].dport:
            return
        if self.ttl * 10 + 1 == packet[IPerror].id:
            self.record_router_ip_found_by_syn(packet.src, packet)
        elif self.ttl * 10 + 2 == packet[IPerror].id:
            self.record_router_ip_found_by_http_get(packet.src, packet)
        else:
            self.report['PACKETS'].append(('UNKNOWN', packet))


    def record_syn_ack(self, packet):
        if self.report['SYN_ACK?']:
            self.report['PACKETS'].append(('ADDITIONAL_SYN_ACK', packet))
        else:
            self.report['PACKETS'].append(('SYN_ACK', packet))
            self.report['SYN_ACK?'] = True

    def record_rst_after_syn(self, packet):
        if self.report['RST_AFTER_SYN?']:
            self.report['PACKETS'].append(('ADDITIONAL_RST_AFTER_SYN', packet))
        else:
            self.report['PACKETS'].append(('RST_AFTER_SYN', packet))
            self.report['RST_AFTER_SYN?'] = True

    def record_rst_after_http_get(self, packet):
        if self.report['RST_AFTER_HTTP_GET?']:
            self.report['PACKETS'].append(('ADDITIONAL_RST_AFTER_HTTP_GET', packet))
        else:
            self.report['PACKETS'].append(('RST_AFTER_HTTP_GET', packet))
            self.report['RST_AFTER_HTTP_GET?'] = True

    def record_router_ip_found_by_syn(self, router_ip, packet):
        if self.report['ROUTER_IP_FOUND_BY_SYN']:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP_FOUND_BY_SYN', packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP_FOUND_BY_SYN', packet))
            self.report['ROUTER_IP_FOUND_BY_SYN'] = router_ip

    def record_router_ip_found_by_http_get(self, router_ip, packet):
        if self.report['ROUTER_IP_FOUND_BY_HTTP_GET']:
            self.report['PACKETS'].append(('ADDITIONAL_ROUTER_IP_FOUND_BY_HTTP_GET', packet))
        else:
            self.report['PACKETS'].append(('ROUTER_IP_FOUND_BY_HTTP_GET', packet))
            self.report['ROUTER_IP_FOUND_BY_HTTP_GET'] = router_ip


if 1 == len(sys.argv):
    print('[Usage] ./http_tcp_rst_probe.py destination_ip ttl')
    sys.exit(3)
else:
    main(*sys.argv[1:])