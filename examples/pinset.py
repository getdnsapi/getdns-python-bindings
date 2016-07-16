#
# Note that we expect that each pin in the pinset list
#   must be prefaced with pin-<algorithm>= and the pin 
#   itself must be base64-encoded and enclosed in double-
#   quotes.  We may loosen this up in a future version
#

import getdns
c = getdns.Context()
u = [ { 'address_data': '185.49.141.38', 
        'address_type': 'IPv4', 
        'tls_pubkey_pinset': ['pin-sha256="foxZRnIh9gZpWnl+zEiKa0EJ2rdCGroMWm02gaxSc9S="']
 }]
c.resolution_type = getdns.RESOLUTION_STUB
c.dns_transport_list = [ getdns.TRANSPORT_TLS ]
c.upstream_recursive_servers = u
f = c.address('getdnsapi.net')
