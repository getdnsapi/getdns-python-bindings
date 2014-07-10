#!/usr/bin/python

import getdns, pprint, sys

def main():
    if len(sys.argv) != 2:
        print "Usage: {0} hostname".format(sys.argv[0])
        sys.exit(1)

    ctx = getdns.Context()
    extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }
    results = ctx.address(name=sys.argv[1], extensions=extensions)
    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        sys.stdout.write("Addresses: ")
        
        for addr in results["just_address_answers"]:
            print " {0}".format(addr["IPSTRING"])
        sys.stdout.write("\n\n")
        print "Entire results tree: "
        pprint.pprint(results)
    if results["status"] == getdns.GETDNS_RESPSTATUS_NO_NAME:
        print "{0} not found".format(sys.argv[1])


if __name__ == "__main__":
    main()
