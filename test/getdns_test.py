import getdns
import inspect
import StringIO
import unittest

class TestGetdnsMethods(unittest.TestCase):
    def test_context(self):
        c = getdns.Context()
        self.assertIsNotNone(c)
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
