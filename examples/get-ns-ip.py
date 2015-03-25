#!/usr/bin/env python
#

"""
Lookup an NS record and printout all the hostnames and associated IP
addresses of the listed nameservers.
"""

import getdns, pprint, sys

extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }


def usage():
    print """Usage: get-ns-ip.py <zone>

where <zone> is a DNS zone (domain).
"""
    sys.exit(1)


def get_ip(ctx, qname):
    iplist = []
    try:
        results = ctx.address(name=qname, extensions=extensions)
    except getdns.error, e:
        print(str(e))
        sys.exit(1)

    if results.status == getdns.GETDNS_RESPSTATUS_GOOD:
        for addr in results.just_address_answers:
            iplist.append(addr['address_data'])
    else:
        print "getdns.address() returned an error: %d" % results['status']
    return iplist


if __name__ == '__main__':

    if len(sys.argv) != 2:
        usage()

    qname = sys.argv[1]

    ctx = getdns.Context()
    try:
        results = ctx.general(name=qname, request_type=getdns.GETDNS_RRTYPE_NS)
    except getdns.error, e:
        print(str(e))
        sys.exit(1)
    status = results.status

    hostlist = []
    if status == getdns.GETDNS_RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            answers = reply['answer']
            for answer in answers:
                if answer['type'] == getdns.GETDNS_RRTYPE_NS:
                    iplist = get_ip(ctx, answer['rdata']['nsdname'])
                    for ip in iplist:
                        hostlist.append( (answer['rdata']['nsdname'], ip) )
    elif status == getdns.GETDNS_RESPSTATUS_NO_NAME:
        print "%s: no such DNS zone" % qname
    elif status == getdns.GETDNS_RESPSTATUS_ALL_TIMEOUT:
        print "%s, NS: query timed out" % qname
    else:
        print "%s, %s: unknown return code: %d" % results["status"]

    # Print out each NS server name and IP address
    for (nsdname, addr) in sorted(hostlist):
        print nsdname, addr
