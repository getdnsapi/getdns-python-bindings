#!/usr/bin/env python

import getdns, sys

hostname = sys.argv[1]

ctx = getdns.Context()
extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }
results = ctx.address(name=hostname, extensions=extensions)

if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
    for addr in results["just_address_answers"]:
        print addr["IPSTRING"]
else:
    print "getdns.address() returned an error: %d" % results["status"]

