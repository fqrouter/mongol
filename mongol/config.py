sniffer_type = 'L2' # can be L3 or Tcpdump, but L2 is working more reliably
min_ttl = 3
max_ttl = 20
debug = True
fixed_route = None
# uncomment below if you have a broken routing table
# which caused the detected outgoing ip or interface is wrong
#fixed_route = ('venet0:0', 'a.b.c.d')
interval_between_poke_and_peek = 2
batch_size = 4
output_dir = 'var'
# tcp_route_probe must not be None
# it is used to test if route changes when sport/dport changed
tcp_route_probe = {
    'a_sport': 9264,
    'b_sport': 8375,
    'c_sport': 7486,
    'a_dport': 6597,
    'b_dport': 5618,
    'c_dport': 4729
}
# udp_route_probe must not be None
# it is used to test if route changes when sport/dport changed
udp_route_probe = {
    'a_sport': 9264,
    'b_sport': 8375,
    'c_sport': 7486,
    'a_dport': 6597,
    'b_dport': 5618,
    'c_dport': 4729
}
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
tcp_packet_drop_probe = None
# uncomment below if you have tcp port being blocked by GFW
# if dport is blocked, set the sport to the same
# if sport is blocked, set the dport to the same
# example below demonstrated the case which sport 8080 is blocked
#tcp_packet_drop_probe = {
#    'blocked_sport': 8080,
#    'comparison_sport': 8081,
#    'blocked_dport': 1234,
#    'comparison_dport': 1234
#}
udp_packet_drop_probe = None
# uncomment below if you have udp port being blocked by GFW
# if dport is blocked, set the sport to the same
# if sport is blocked, set the dport to the same
# example below demonstrated the case which sport 8080 is blocked
#udp_packet_drop_probe = {
#    'blocked_sport': 8080,
#    'comparison_sport': 8081,
#    'blocked_dport': 53,
#    'comparison_dport': 53
#}
# config below works whne you probe from abroad to China
# if you want to probe from China to abroad, change the settings below
# to provide abroad ip
ip_providers = [
    'by_carrier.py CHINANET | limit.py 50',
    'by_carrier.py CNCGROUP | limit.py 50',
    'by_carrier.py CN-CMCC | limit.py 50',
    'by_carrier.py CN-CRTC | limit.py 50',
    'by_carrier.py CERNET-AP | limit.py 50',
    'by_carrier.py CN-CSTNET | limit.py 50'
]
as_providers = [
    'by_country.py CN asn'
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

if not os.path.exists(output_dir):
    os.mkdir(output_dir)