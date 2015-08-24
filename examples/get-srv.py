#!/usr/bin/env python
#

"""
Lookup an SRV record and printout all the SRV priority, weight, targets, 
and associated IP addresses of the targets.
"""

import getdns, pprint, sys, time

srvname = sys.argv[1]

ctx = getdns.Context()
try:
    results = ctx.service(name=srvname)
except getdns.error as e:
    print(str(e))
    sys.exit(1)

if results.status == getdns.RESPSTATUS_GOOD:
    for reply in results.replies_tree:
        for a in reply["answer"]:
            rrname  = a["name"]
            rrtype  = a["type"]
            if rrtype == getdns.RRTYPE_SRV:
                rdata   = a["rdata"]
                prio, weight, port, target = rdata['priority'], rdata['weight'], rdata['port'], rdata['target']
                print("SRV {0} --> {1} {2} {3} {4}".format(rrname, prio, weight, port, target))
else:
    print("getdns.service() returned an error: {0}".format(results.status))
