import getdns
import inspect
import StringIO
import sys, platform
import unittest


un = platform.uname()
d = 'lib.' + un[0].lower() + '-' + un[4] + '-' + '.'.join(platform.python_version().split('.')[:2])
sys.path.append(d)


class TestGetdnsMethods(unittest.TestCase):
    def test_context(self):
        c = getdns.Context()
        self.assertIsNotNone(c)
        del(c)

    def test_append_name(self):
        c = getdns.Context()
        c.append_name = getdns.APPEND_NAME_NEVER
        self.assertEqual(c.append_name, getdns.APPEND_NAME_NEVER)
        del(c)

    def test_dns_root_servers(self):
        c = getdns.Context()
        addrs = [ { 'address_type': 'IPv4', 'address_data': '127.0.0.254' } ]
        c.dns_root_servers = addrs
        self.assertEqual(c.dns_root_servers, addrs)
        del(c)


    def test_sync_address(self):
        c = getdns.Context()
        c.resolution_type=getdns.RESOLUTION_STUB
        r = c.address('www.getdnsapi.net')
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        self.assertTrue('185.49.141.37' in [ x['address_data'] for x in r.just_address_answers ])
        del(c)
        del(r)

    def test_sync_service(self):
        c = getdns.Context()
        c.resolution_type=getdns.RESOLUTION_STUB
        r = c.service('_xmpp-server._tcp.jabber.org')
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        del(c)
        del(r)

    def test_sync_hostname(self):
        c = getdns.Context()
        c.resolution_type=getdns.RESOLUTION_STUB
        r = c.hostname( { 'address_type': 'IPv4', 'address_data': '185.49.141.37' } )
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        del(c)
        del(r)

    def test_sync_general(self):
        c = getdns.Context()
        c.resolution_type=getdns.RESOLUTION_STUB
        r = c.general('nlnetlabs.nl', request_type=getdns.RRTYPE_NS)
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        del(c)
        del(r)

    def test_file_to_list(self):
        ns1 = {'class': 1,
               'name': 'example.com.',
               'rdata': {'nsdname': 'ns1.example.com.',
                         'rdata_raw':'ns1.example.com.'},
               'ttl': 3600,
               'type': 2
               }
        ns2 = {'class': 1,
               'name': 'example.com.',
               'rdata': {'nsdname': 'ns2.example.com.',
                         'rdata_raw': 'ns2.example.com.'},
               'ttl': 3600,
               'type': 2
               }
        f = open('example.com.zone')
        r = getdns.file_to_list(f, 'example.com', 3600 )
        self.assertIsInstance(r, list)
        self.assertEqual(r[1], ns1)
        self.assertEqual(r[2], ns2)
        del(f)
        del(r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
