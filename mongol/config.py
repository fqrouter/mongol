sniffer_type = 'L3'
interval_between_poke_and_peek = 2
interval_between_syn_and_http_get = 0.5
interval_between_syn_and_dns_question = 0.5
dns_wrong_answer_probe_sport = 19841
dns_wrong_answer_probe_dport = 53
http_tcp_rst_probe_sport = 19842
http_tcp_rst_probe_dport = 80
dns_tcp_rst_probe_sport = 19843
dns_tcp_rst_probe_dport = 53
min_ttl = 4
max_ttl = 14
debug = True
blocked_tcp_port = None
comparison_tcp_port = None
blocked_udp_port = None
comparison_udp_port = None
fixed_route = None # ('venet0:0', 'a.b.c.d')

import os
import sys

MONGOL_CFG_PATH = os.path.join(os.getenv('HOME'), '.mongol.cfg')
if os.path.exists(MONGOL_CFG_PATH):
    with open(MONGOL_CFG_PATH) as f:
        user_config_code = compile(f.read(), MONGOL_CFG_PATH, 'exec')
    user_config = {}
    exec user_config_code in user_config
    sys.modules[__name__].__dict__.update(user_config)