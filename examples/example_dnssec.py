#!/usr/bin/python

import getdns, pprint, sys

dnssec_status = {
    "GETDNS_DNSSEC_SECURE" : 400,
    "GETDNS_DNSSEC_BOGUS" : 401,
    "GETDNS_DNSSEC_INDETERINATE" : 402,
    "GETDNS_DNSSEC_INSECURE" : 403,
    "GETDNS_DNSSEC_NOT_PERFORMED" : 404
}


def dnssec_message(value):
    for message in dnssec_status.keys():
        if dnssec_status[message] == value:
            return message

def main():
    if len(sys.argv) != 2:
        print "Usage: {0} hostname".format(sys.argv[0])
        sys.exit(1)

    ctx = getdns.context_create()
    extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE,
                   "dnssec_return_status" : getdns.GETDNS_EXTENSION_TRUE }
    results = getdns.address(ctx, name=sys.argv[1], extensions=extensions)
    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        sys.stdout.write("Addresses: ")
        for addr in results["just_address_answers"]:
            print " {0}".format(addr["IPSTRING"])
        sys.stdout.write("\n")

        for result in results["replies_tree"]:
            if "dnssec_status" in result.keys():
                print "{0}: dnssec_status: {1}".format(result["canonical_name"],
                                                       dnssec_message(result["dnssec_status"]))

    if results["status"] == getdns.GETDNS_RESPSTATUS_NO_NAME:
        print "{0} not found".format(sys.argv[1])


if __name__ == "__main__":
    main()
