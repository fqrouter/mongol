from scapy.layers.inet import TCP, UDP
import socket

raw_socket = None

def send(packet):
    if UDP in packet:
        get_socket().sendto(str(packet), (packet.dst, packet[UDP].dport))
    elif TCP in packet:
        get_socket().sendto(str(packet), (packet.dst, packet[TCP].dport))
    else:
        raise Exception('packet is neither UDP nor TCP')


def get_socket():
    global raw_socket
    if raw_socket:
        return raw_socket
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    return raw_socket