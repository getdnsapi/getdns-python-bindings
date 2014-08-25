#!/usr/bin/env python
#

"""
Lookup an SRV record and printout all the SRV priority, weight, targets, 
and associated IP addresses of the targets.
"""

import getdns, pprint, sys, time

srvname = sys.argv[1]

ctx = getdns.Context()
results = ctx.service(name=srvname)

if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
    for reply in results["replies_tree"]:
        for a in reply["answer"]:
            rrname  = a["name"]
            rrtype  = a["type"]
            if rrtype == getdns.GETDNS_RRTYPE_SRV:
                rdata   = a["rdata"]
                prio, weight, port, target = rdata['priority'], rdata['weight'], rdata['port'], rdata['target']
                print "SRV %s --> %d %d %d %s" % \
                    (rrname, prio, weight, port, target)
else:
    print "getdns.service() returned an error: %d" % results["status"]
