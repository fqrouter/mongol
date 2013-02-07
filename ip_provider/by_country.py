#!/usr/bin/env python
import socket
import struct
import random
import sys
import urllib2

# Generate random ip from ip range of specific country

def main(target_country='CN'):
    response = urllib2.urlopen('http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest')
    lines = [line for line in response.read().splitlines() if '|ipv4|' in line]
    for line in lines[1:]:
        _, country, _, start_ip, ip_count, _, _ = line.split('|')
        if target_country == country:
            print(get_random_ip_in_range(start_ip, int(ip_count)))


def get_random_ip_in_range(start_ip, ip_count):
# http://dregsoft.com/blog/?p=24
    start_ip_bytes = struct.unpack('!i', socket.inet_aton(start_ip))[0]
    random_ip_bytes = random.randrange(start_ip_bytes, start_ip_bytes + ip_count)
    random_ip = socket.inet_ntoa(struct.pack('!i', random_ip_bytes))
    return random_ip

if 1 == len(sys.argv):
    print('[Usage] ./by_country.py two_letter_country_code > ip_list.txt')
    print('Lookup http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 to find out')
    sys.exit(3)
else:
    main(*sys.argv[1:])