#!/usr/bin/env python

import getdns, sys

hostname = sys.argv[1]

ctx = getdns.Context()
ctx.resolution_type = getdns.GETDNS_RESOLUTION_STUB

extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }
ctx.resolver_type = getdns.GETDNS_RESOLUTION_STUB

results = ctx.address(name=hostname, extensions=extensions)

if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
    for addr in results["just_address_answers"]:
        print addr["address_data"]
else:
    print "getdns.address() returned an error: %d" % results["status"]

