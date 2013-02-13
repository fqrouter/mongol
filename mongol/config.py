sniffer_type = 'L2'
min_ttl = 6
max_ttl = 14
debug = True
fixed_route = None # ('venet0:0', 'a.b.c.d')
interval_between_poke_and_peek = 2
batch_size = 4
dns_wrong_answer_probe = {
    'sport': 19841,
    'dport': 53
}
http_tcp_rst_probe = {
    'sport': 19842,
    'dport': 80,
    'interval_between_syn_and_http_get': 0.5
}
dns_tcp_rst_probe = {
    'sport': 19843,
    'dport': 53,
    'interval_between_syn_and_dns_question': 0.5
}
tcp_packet_drop_probe = {
    'blocked_sport': 8080,
    'comparison_sport': 8081,
    'dport': 1234
}
udp_packet_drop_probe = None
#udp_packet_drop_probe = {
#    'blocked_sport': 8080,
#    'comparison_sport': 8081,
#    'dport': 53
#}
ip_providers = [
    'by_carrier.py CHINANET | limit.py 50',
    'by_carrier.py CNCGROUP | limit.py 50',
    'by_carrier.py CN-CMCC | limit.py 50',
    'by_carrier.py CN-CRTC | limit.py 50',
    'by_carrier.py CERNET-AP | limit.py 50',
    'by_carrier.py CN-CSTNET | limit.py 50'
]

import os
import sys

MONGOL_CFG_PATH = os.path.join(os.getenv('HOME'), '.mongol.cfg')
if os.path.exists(MONGOL_CFG_PATH):
    with open(MONGOL_CFG_PATH) as f:
        user_config_code = compile(f.read(), MONGOL_CFG_PATH, 'exec')
    user_config = {}
    exec user_config_code in user_config
    sys.modules[__name__].__dict__.update(user_config)