import getdns
c = getdns.context_create()
ext = { "return_both_v4_and_v6" :  getdns.GETDNS_EXTENSION_TRUE }
ret  = getdns.general(c, "www.google.com", getdns.GETDNS_RRTYPE_A, ext)
print ret
ret  = getdns.reply_full(c, "gmail.com", getdns.GETDNS_RRTYPE_A, ext)
print ret
print ret['output']['just_address_answers']
print ret['output']['replies_tree']
print ret['output']['replies_tree'][0]['answer']
print ret['output']['replies_tree'][0]['answer_type']
print ret['output']['replies_tree'][0]['header']
print ret['output']['replies_tree'][0]['answer']['question']
print ret['output']['replies_tree'][0]['question']
print ret['output']['status']
ret  = getdns.reply_full(c, "gmail.com", getdns.GETDNS_RRTYPE_MX, ext)
print ret
ret  = getdns.replies_tree(c, "www.google.com", getdns.GETDNS_RRTYPE_A, ext)
print ret
ret  = getdns.replies_tree(c, "panix.com", getdns.GETDNS_RRTYPE_A, ext)
print ret
ret  = getdns.replies_tree(c, "panix.com", getdns.GETDNS_RRTYPE_NS, ext)
print ret
ret  = getdns.replies_tree(c, "panix.com", getdns.GETDNS_RRTYPE_SOA, ext)
print ret
