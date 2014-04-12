#!/usr/bin/python

import getdns, pprint, sys, string

def main():
    addr = {}

    if len(sys.argv) != 2:
        print "Usage: {0} ipaddress".format(sys.argv[0])
        sys.exit(1)

    ctx = getdns.context_create()
    addr["address_data"] = sys.argv[1]
    if string.find(sys.argv[1], ":") != -1:
        addr["address_type"] = "IPv6"
    elif string.find(sys.argv[1], ".") != 1:
        addr["address_type"] = "IPv4"
    else:
        print "{0}: undiscernable address type".format(sys.argv[1])
        sys.exit(1)
    results = getdns.hostname(ctx, address=addr)
    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        print "Hostnames:"
        for responses in results["replies_tree"]:
            for ans in responses["answer"]:
                print string.rstrip(ans["rdata"]["ptrdname"], ".")

    if results["status"] == getdns.GETDNS_RESPSTATUS_NO_NAME:
        print "{0} not found".format(sys.argv[1])


if __name__ == "__main__":
    main()
