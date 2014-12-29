#!/usr/bin/env python
#

"""
simply.py

A simple example to query a domain name and print out addresses
associated with it.
"""

import sys, getdns

hostname = sys.argv[1]

ctx = getdns.Context()
extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }

try:
    results = ctx.address(name=hostname, extensions=extensions)
except getdns.error, e:
    print(str(e))
    sys.exit(1)

status = results['status']

if status == getdns.GETDNS_RESPSTATUS_GOOD:
    for addr in results['just_address_answers']:
        print addr['address_data']
else:
    print "%s: getdns.address() returned error: %d" % (hostname, status)
