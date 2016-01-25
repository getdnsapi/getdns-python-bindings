
# an example of using getdns to pull out a TLSA record,
# extract a certificate, extract the public key, and then
# encrypt some text
#
# requires the following Python modules:
#    getdns
#    m2crypto
#


import getdns
import M2Crypto as m2
from M2Crypto import RSA
import sys



# 
# I commented out the "return None" because this is demo code and you
# should be able to play with it.  But, in deployed applications you
# MUST check that dnssec_status is DNSSEC_SECURE
#

def get_first_secure_response(results):
    replies_tree = results.replies_tree
    if (not replies_tree) or (not len(replies_tree)) or (not replies_tree[0]['answer']) or (not len(replies_tree[0]['answer'])):
        print 'empty answer list'
        return None
    else:
        reply = replies_tree[0]
        if reply['dnssec_status'] != getdns.DNSSEC_SECURE:
            print 'insecure reply'
#            return None                      
        answer = replies_tree[0]['answer']
        record = [ x for x in answer if x['type'] is getdns.RRTYPE_TLSA ]
        if len(record) == 0:
            print 'no answers of type TLSA'
            return None
        return record[0]
    
def main():
    tls_name = '77fa5113ab6a532ce2e6901f3bd3351c0db5845e0b1b5fb09907808d._smimecert.getdnsapi.org'

    if len(sys.argv) == 2:
        tls_name = sys.argv[1]
    c = getdns.Context()
    extensions = { 'dnssec_return_status' : getdns.EXTENSION_TRUE }
    results = c.general(tls_name, request_type=getdns.RRTYPE_TLSA, extensions=extensions)
    if results.replies_full['status'] != getdns.RESPSTATUS_GOOD:
        print 'query status is {0}'.format(results.status)
        sys.exit(1)
    else:
        record = get_first_secure_response(results)
        cert = record['rdata']['certificate_association_data']
        try:
            x509 = m2.X509.load_cert_der_string(cert)
            rsakey = x509.get_pubkey().get_rsa()
            encrypted = rsakey.public_encrypt("A chunk of text", RSA.pkcs1_oaep_padding)
            print encrypted.encode('base64')
        except:
            print 'Error: ', sys.exc_info()[0]
            sys.exit(1)

if __name__ == '__main__':
    main()
