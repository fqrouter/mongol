__import__('scapy.route')
from scapy.config import conf
import os

OUTBOUND_IFACE = os.getenv('OUTBOUND_IFACE')
OUTBOUND_IP = os.getenv('OUTBOUND_IP')
if OUTBOUND_IFACE and OUTBOUND_IP:
    conf.route.ifadd(OUTBOUND_IFACE, '%s/0' % OUTBOUND_IP)

def get_route(dst):
    return conf.route.route(dst)