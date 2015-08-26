#!/usr/bin/env python
#

"""
simple.py

A simple example to query a domain name and print out addresses
associated with it.
"""

import sys, getdns

hostname = sys.argv[1]

ctx = getdns.Context()
extensions = { 'return_both_v4_and_v6' : getdns.EXTENSION_TRUE }

try:
    results = ctx.address(name=hostname, extensions=extensions)
except:
    e = sys.exc.info()[0]
    print(str(e))
    sys.exit(1)

status = results.status

if status == getdns.RESPSTATUS_GOOD:
    for addr in results.just_address_answers:
        print (addr['address_data'])
else:
    print("{0}: getdns.address() returned error: {1}".format((hostname, status)))
