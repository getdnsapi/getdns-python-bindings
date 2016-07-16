#!/usr/bin/env python
#

"""
get-ip.py: resolve given DNS names into IP addresses. The -s switch
constains answers to only ones secured by DNSSEC. The -4 switch only
returns IPv4 addresses, the -6 switch only IPv6 addresses.

An example run:
$ python async-get-ip.py www.panix.com www.isoc.org www.verisignlabs.com

submitted query for www.panix.com
submitted query for www.isoc.org
submitted query for www.verisignlabs.com
www.panix.com: IPv4 166.84.62.125
www.panix.com: IPv4 166.84.62.253
www.verisignlabs.com: IPv4 72.13.58.64
www.verisignlabs.com: IPv6 2620:74:13:4400::201
www.isoc.org: IPv4 212.110.167.157
www.isoc.org: IPv6 2001:41c8:20::19

"""

import getdns, sys, getopt

desired_addr_type = None

def cbk(type, result, userarg, tid):
    if type == getdns.CALLBACK_COMPLETE:
        status = result.status
        if status == getdns.RESPSTATUS_GOOD:
            for addr in result.just_address_answers:
                addr_type = addr['address_type']
                addr_data = addr['address_data']
                if (desired_addr_type == None) or (addr_type == desired_addr_type):
                    print("{0}: {1} {2}".format(userarg, addr_type, addr_data))
        elif status == getdns.RESPSTATUS_NO_SECURE_ANSWERS:
            print("{0}: No DNSSEC secured responses found".format(hostname))
        else:
            print("{0}: getdns.address() returned error: {1}".format(hostname, status))
    elif type == getdns.CALLBACK_CANCEL:
        print('Callback cancelled')
    elif type == getdns.CALLBACK_TIMEOUT:
        print('Query timed out')
    else:
        print('Unknown error')


def usage():
    print("""\
Usage: get-ip.py [-s] [-4|-6] <domain1> <domain2> ...

    -s: only return DNSSEC secured answers
    -4: only return IPv4 address answers
    -6: only return IPv6 address answers

-4 and -6 are mutually exclusive. If both are specified, IPv6 wins.
""")
    sys.exit(1)

try:
    (options, args) = getopt.getopt(sys.argv[1:], 's46')
except getopt.GetoptError:
    usage()
else:
    if not args:
        usage()

extensions = { "return_both_v4_and_v6" : getdns.EXTENSION_TRUE }

for (opt, optval) in options:
    if opt == "-s":
        extensions["dnssec_return_only_secure"] = getdns.EXTENSION_TRUE
    elif opt == "-4":
        desired_addr_type = "IPv4"
    elif opt == "-6":
        desired_addr_type = "IPv6"

ctx = getdns.Context()
tids = []
for hostname in args:
    try:
        tids.append(ctx.address(name=hostname, extensions=extensions, callback='cbk', userarg=hostname))
        print ('submitted query for {0}'.format(hostname))
    except getdns.error as e:
        print(str(e))
        break
ctx.run()
