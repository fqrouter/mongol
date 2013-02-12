from .routing_table import get_route
from .raw_socket_sender import send
from .l3_sniffer import dump_socket

def create_sniffer(iface, src, dst):
# sniffer can be: L3Sniffer, L2Sniffer or TcpdumpSniffer
    from .l3_sniffer import L3Sniffer

    return L3Sniffer(src, dst)

__all__ = [
    get_route.__name__,
    send.__name__,
    create_sniffer.__name__,
    dump_socket.__name__
]
