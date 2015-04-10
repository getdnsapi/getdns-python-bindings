#!/usr/bin/env python
#
# Validate a TLS certificate with DANE-EE usage.
# Get a TLS certificate from a HTTP server and verify it with
# DANE/DNSSEC. Only supports TLSA usage=3 (DANE-EE)
# 

import os.path, sys, socket, hashlib
from M2Crypto import SSL, X509
import getdns


def usage():
    print """\
Usage: %s [hostname] [port]\
""" % os.path.basename(sys.argv[0])
    sys.exit(1)


def compute_hash(func, string):
    """compute hash of string using given hash function"""
    h = func()
    h.update(string)
    return h.hexdigest()


def get_addresses(hostname):

    extensions = {
        "return_both_v4_and_v6" : getdns.EXTENSION_TRUE
    }
    ctx = getdns.Context()
    try:
        results = ctx.address(name=hostname, extensions=extensions)
    except getdns.error, e:
        print(str(e))
        sys.exit(1)

    status = results.status

    address_list = []
    if status == getdns.RESPSTATUS_GOOD:
        for addr in results.just_address_answers:
            address_list.append((addr['address_type'], addr['address_data']))
    else:
        print "getdns.address(): failed, return code: %d" % status

    return address_list


def get_tlsa_rdata_set(replies, requested_usage=None):
    tlsa_rdata_set = []
    for reply in replies:
        for rr in reply['answer']:
            if rr['type'] == getdns.RRTYPE_TLSA:
                rdata = rr['rdata']
                usage = rdata['certificate_usage']
                selector = rdata['selector']
                matching_type = rdata['matching_type']
                cadata = rdata['certificate_association_data']
                cadata = str(cadata).encode('hex')
                if usage == requested_usage:
                    tlsa_rdata_set.append(
                        (usage, selector, matching_type, cadata) )
    return tlsa_rdata_set


def get_tlsa(port, proto, hostname):

    extensions = {
        "dnssec_return_only_secure" : getdns.EXTENSION_TRUE,
    }
    qname = "_%d._%s.%s" % (port, proto, hostname)
    ctx = getdns.Context()
    try:
        results = ctx.general(name=qname,
                              request_type=getdns.RRTYPE_TLSA,
                              extensions=extensions)
    except getdns.error, e:
        print(str(e))
        sys.exit(1)

    status = results.status

    if status == getdns.RESPSTATUS_GOOD:
        return get_tlsa_rdata_set(results.replies_tree, requested_usage=3)
    else:
        print "getdns.general(): failed, return code: %d" % status
        return None


def verify_tlsa(cert, usage, selector, matchtype, hexdata1):

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

    try:
        hostname, port = sys.argv[1:]
        port = int(port)
    except:
        usage()

    tlsa_rdata_set = get_tlsa(port, "tcp", hostname)

    for (iptype, ipaddr) in get_addresses(hostname):

        print "Connecting to %s at address %s ..." % (hostname, ipaddr)
        ctx = SSL.Context()

        if iptype == "IPv4":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif iptype == "IPv6":
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            raise ValueError, "Unknown address type: %s" % iptype

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        connection = SSL.Connection(ctx, sock=sock)

        # set TLS SNI extension if available in M2Crypto on this platform
        # Note: the official M2Crypto release does not yet (as of late 2014)
        # have support for SNI, sigh, but patches exist.
        try:
            connection.set_tlsext_host_name(hostname)
        except AttributeError:
            pass

        # Per https://tools.ietf.org/html/draft-ietf-dane-ops, for DANE-EE
        # usage, certificate identity checks are based solely on the TLSA 
        # record, so we ignore name mismatch conditions in the certificate.
        try:
            connection.connect((ipaddr, port))
        except SSL.Checker.WrongHost:
            pass

        chain = connection.get_peer_cert_chain()
        cert = chain[0]

        # find a matching TLSA record entry for the certificate
        tlsa_match = False
        for (usage, selector, matchtype, hexdata) in tlsa_rdata_set:
            if verify_tlsa(cert, usage, selector, matchtype, hexdata):
                tlsa_match = True
                print "Matched TLSA record %d %d %d %s" % \
                    (usage, selector, matchtype, hexdata)
            else:
                print "Didn't match TLSA record %d %d %d %s"% \
                    (usage, selector, matchtype, hexdata)

        if not tlsa_match:
            print "No Matching DANE-EE TLSA record found."

        connection.close()
        ctx.close()

