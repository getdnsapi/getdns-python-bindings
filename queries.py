import getdns
import pprint
c = getdns.context_create()
ext = { "return_both_v4_and_v6" :  getdns.GETDNS_EXTENSION_TRUE }
ret  = getdns.general(c, "www.google.com", getdns.GETDNS_RRTYPE_A, ext)
print ret
pprint.pprint(getdns.replies_tree(c, "gmail.com", getdns.GETDNS_RRTYPE_A, ext))
pprint.pprint(getdns.replies_tree(c, "gmail.com", getdns.GETDNS_RRTYPE_AAAA, ext))
pprint.pprint(getdns.replies_tree(c, "gmail.com", getdns.GETDNS_RRTYPE_TXT, ext))
pprint.pprint(getdns.replies_tree(c, "panix.com", getdns.GETDNS_RRTYPE_A, ext))
pprint.pprint(getdns.replies_tree(c, "panix.com", getdns.GETDNS_RRTYPE_NS, ext))
pprint.pprint(getdns.replies_tree(c, "panix.com", getdns.GETDNS_RRTYPE_SOA, ext))
pprint.pprint(getdns.replies_tree(c, "www.example.com", getdns.GETDNS_RRTYPE_A, ext))
ext = { "dnssec_return_validation_chain" : getdns.GETDNS_EXTENSION_TRUE }
pprint.pprint(getdns.replies_tree(c, "www.example.com", getdns.GETDNS_RRTYPE_A, ext))
ext = { "dnssec_return_status" : getdns.GETDNS_EXTENSION_TRUE }
pprint.pprint(getdns.replies_tree(c, "www.example.com", getdns.GETDNS_RRTYPE_A, ext))
ext = { "dnssec_return_validation_chain" : getdns.GETDNS_EXTENSION_TRUE }
pprint.pprint(getdns.replies_tree(c, "good.dane.verisignlabs.com", getdns.GETDNS_RRTYPE_A, ext))
pprint.pprint(getdns.replies_tree(c, "bad.dane.verisignlabs.com", getdns.GETDNS_RRTYPE_TLSA, ext))
