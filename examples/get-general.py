#!/usr/bin/env python
#
# Given a DNS name and type, return the records in the DNS answer
# section only, excluding any RRSIG records.
#

import getdns, pprint, sys

extensions = { "dnssec_return_status" : getdns.EXTENSION_TRUE }

def get_rrtype(qtype):
    try:
        rrtype = eval("getdns.RRTYPE_%s" % qtype.upper())
    except AttributeError:
        print("Unknown DNS record type: {0}".format(qtype))
        sys.exit(1)
    else:
        return rrtype


def print_answer(r):
    pprint.pprint(r.replies_tree[0]['answer'])
    return


if __name__ == '__main__':

    qname, qtype = sys.argv[1:]
    rrtype = get_rrtype(qtype)

    ctx = getdns.Context()
    try:
        results = ctx.general(name=qname, request_type=rrtype,
                              extensions=extensions)
    except getdns.error as e:
        print(str(e))
        sys.exit(1)

    status = results.status

    if status == getdns.RESPSTATUS_GOOD:
        for reply in results.replies_tree:
            answers = reply['answer']           # list of 1 here
            for answer in answers:
                if answer['type'] != getdns.RRTYPE_RRSIG:
                    pprint.pprint(answer)
    elif status == getdns.RESPSTATUS_NO_NAME:
        print("{0}, {1}: no such name".format(qname, qtype))
    elif status == getdns.RESPSTATUS_ALL_TIMEOUT:
        print("{0}, {1}: query timed out".format(qname, qtype))
    else:
        print("{0}, {1}: unknown return code: {2}".format(qname, qtype, results.status))

