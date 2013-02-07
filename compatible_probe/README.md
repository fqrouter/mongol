#compatible probe

Compatible probe does not use raw socket to send packet, instead it uses normal UDP or TCP socket but set ttl
using socket options. ~~It is useful in environment such as OpenVZ container with venet network adapter.~~
It was a mistake, OpenVZ container with venet network adapter can send packet using raw socket. So compatible
probe does not have any advantage over direct probe.