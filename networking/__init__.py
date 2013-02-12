from .routing_table import get_route
from .raw_socket_sender import send
from .l3_sniffer import dump_socket

def create_sniffer(iface, src, dst):
# sniffer can be: L3Sniffer, L2Sniffer or TcpdumpSniffer
    from .l3_sniffer import L3Sniffer

    return L3Sniffer(src, dst)


def immediately_close_tcp_socket_so_sport_can_be_reused(tcp_socket):
    import socket
    import struct

    if not tcp_socket:
        return
    l_onoff = 1
    l_linger = 0
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
    tcp_socket.close()

__all__ = [
    get_route.__name__,
    send.__name__,
    create_sniffer.__name__,
    dump_socket.__name__,
    immediately_close_tcp_socket_so_sport_can_be_reused.__name__
]
