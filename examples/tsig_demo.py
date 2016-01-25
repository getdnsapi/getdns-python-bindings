import getdns
import base64

u = [ { 'address_data': '185.49.141.37', 
        'address_type': 'IPv4', 
        'tsig_algorithm': 'hmac-md5.sig-alg.reg.int', 
        'tsig_name': 'hmac-md5.tsigs.getdnsapi.net',
        'tsig_secret':  base64.b64decode('16G69OTeXW6xSQ==')
 }]

c = getdns.Context()
c.resolution_type = getdns.RESOLUTION_STUB
c.upstream_recursive_servers = u
f = c.general('getdnsapi.net', request_type = getdns.RRTYPE_SOA)
print('tsig_status is {0}'.format(f.replies_tree[0]['tsig_status']))
