#compatible probe

Compatible probe does not use raw socket to send packet, instead it uses normal udp or tcp socket but set ttl
using socket options. It is useful in environment such as OpenVZ container with venet network adapter.