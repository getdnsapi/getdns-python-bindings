#!/usr/bin/env python
#
# Given a DNS name and type, return the records in the DNS answer
# section only, excluding any RRSIG records.
#

import getdns, pprint, sys

extensions = { "dnssec_return_status" : getdns.GETDNS_EXTENSION_TRUE }

def get_rrtype(qtype):
    try:
        rrtype = eval("getdns.GETDNS_RRTYPE_%s" % qtype.upper())
    except AttributeError:
        print "Unknown DNS record type: %s" % qtype
        sys.exit(1)
    else:
        return rrtype


def print_answer(r):
    pprint.pprint(r['replies_tree'][0]['answer'])
    return


if __name__ == '__main__':

    qname, qtype = sys.argv[1:]
    rrtype = get_rrtype(qtype)

    ctx = getdns.Context()
    results = ctx.general(name=qname, request_type=rrtype,
                          extensions=extensions)
    status = results['status']

    if status == getdns.GETDNS_RESPSTATUS_GOOD:
        for reply in results['replies_tree']:
            answers = reply['answer']           # list of 1 here
            for answer in answers:
                if answer['type'] != getdns.GETDNS_RRTYPE_RRSIG:
                    pprint.pprint(answer)
    elif status == getdns.GETDNS_RESPSTATUS_NO_NAME:
        print "%s, %s: no such name" % (qname, qtype)
    elif status == getdns.GETDNS_RESPSTATUS_ALL_TIMEOUT:
        print "%s, %s: query timed out" % (qname, qtype)
    else:
        print "%s, %s: unknown return code: %d" % results["status"]
