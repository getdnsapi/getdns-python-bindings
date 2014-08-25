#!/usr/bin/env python
#
# Get a TLS certificate from a HTTP server and verify it with
# DANE/DNSSEC. Only supports TLSA usage type 3 (DANE-EE).
# 

import sys, socket, hashlib
from M2Crypto import SSL, X509
import getdns


def compute_hash(func, string):
    """compute hash of string using given hash function"""
    h = func()
    h.update(string)
    return h.hexdigest()


def get_tlsa_rdata_set(replies):
    tlsa_rdata_set = []
    for reply in replies:
        for rr in reply['answer']:
            if rr['type'] == getdns.GETDNS_RRTYPE_TLSA:
                rdata = rr['rdata']
                usage = rdata['certificate_usage']
                selector = rdata['selector']
                matching_type = rdata['matching_type']
                cadata = rdata['certificate_association_data']
                cadata = str(cadata).encode('hex')
                tlsa_rdata_set.append(
                    (usage, selector, matching_type, cadata) )
    return tlsa_rdata_set


def get_tlsa(port, proto, hostname):

    qname = "_%d._%s.%s" % (port, proto, hostname)
    ctx = getdns.Context()
    extensions = { "dnssec_return_only_secure": getdns.GETDNS_EXTENSION_TRUE }
    results = ctx.general(name=qname,
                          request_type=getdns.GETDNS_RRTYPE_TLSA,
                          extensions=extensions)
    status = results['status']

    if status == getdns.GETDNS_RESPSTATUS_GOOD:
        return get_tlsa_rdata_set(results['replies_tree'])
    else:
        print "getdns: failed looking up TLSA record, code: %d" % status
        return None


def verify_tlsa(cert, usage, selector, matchtype, hexdata1):

    if usage != 3:
        print "Only TLSA usage type 3 is currently supported"
        return

    if selector == 0:
        certdata = cert.as_der()
    elif selector == 1:
        certdata = cert.get_pubkey().as_der()
    else:
        raise ValueError("selector type %d not recognized" % selector)

    if matchtype == 0:
        hexdata2 = hexdump(certdata)
    elif matchtype == 1:
        hexdata2 = compute_hash(hashlib.sha256, certdata)
    elif matchtype == 2:
        hexdata2 = compute_hash(hashlib.sha512, certdata)
    else:
        raise ValueError("matchtype %d not recognized" % matchtype)

    if hexdata1 == hexdata2:
        return True
    else:
        return False


if __name__ == '__main__':

    hostname, port = sys.argv[1:]
    port = int(port)
    tlsa_rdata_set = get_tlsa(port, "tcp", hostname)

    ctx = SSL.Context()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    connection = SSL.Connection(ctx, sock=sock)
    connection.connect((hostname, port))

    chain = connection.get_peer_cert_chain()
    # Get the first certificate from the chain (which will be the EE cert)
    cert = chain[0]

    # find a matching TLSA record entry for the certificate
    tlsa_match = False
    for (usage, selector, matchtype, hexdata) in tlsa_rdata_set:
        if verify_tlsa(cert, usage, selector, matchtype, hexdata):
            tlsa_match = True
            print "Certificate matched TLSA record %d %d %d %s" % \
                (usage, selector, matchtype, hexdata)
        else:
            print "Certificate did not match TLSA record %d %d %d %s"% \
                (usage, selector, matchtype, hexdata)
    if tlsa_match:
        print "Found at least one matching TLSA record"

    connection.close()
    ctx.close()

