#!/usr/bin/env python

import getdns

u = [ { 'address_data': '9.9.9.9', 'address_type': 'IPv4', } ]

c = getdns.Context()
c.resolution_type = getdns.RESOLUTION_STUB
c.dns_transport_list = [ getdns.TRANSPORT_TLS ]
c.upstream_recursive_servers = u
r = c.address('getdnsapi.net')
if r.status == getdns.RESPSTATUS_GOOD:
    for a in r.just_address_answers:
        print(a['address_data'])
