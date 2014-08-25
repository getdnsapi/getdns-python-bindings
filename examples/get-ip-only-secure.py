#!/usr/bin/env python

import getdns, sys

hostname = sys.argv[1]

ctx = getdns.Context()
extensions = {
    "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE,
    "dnssec_return_only_secure": getdns.GETDNS_EXTENSION_TRUE,
}
results = ctx.address(name=hostname, extensions=extensions)
status = results['status']

if status == getdns.GETDNS_RESPSTATUS_GOOD:
    for addr in results["just_address_answers"]:
        print addr["IPSTRING"]
elif status == getdns.GETDNS_RESPSTATUS_NO_SECURE_ANSWERS:
    print "No DNSSEC secured responses found"
else:
    print "getdns.address() returned error: %d" % status
