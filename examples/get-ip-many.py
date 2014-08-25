#!/usr/bin/env python

import getdns, sys

ctx = getdns.Context()
extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }

for hostname in sys.argv[1:]:
    results = ctx.address(name=hostname, extensions=extensions)
    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        for addr in results["just_address_answers"]:
            print "%s: %s" % (hostname, addr["IPSTRING"])
    else:
        print "getdns.address() returned an error: %d" % results["status"]

