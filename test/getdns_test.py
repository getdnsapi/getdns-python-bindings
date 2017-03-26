#
# unit tests for getdns.  Most of these test that
#   attributes are readable and writable, although
#   there are some functionality tests, as well,
#   and some functionality testing is a byproduct
#   of data tests
#
#   TODO: break these out into a test suite format,
#     add more functionality tests

import getdns
import unittest
import platform, sys, os, random, base64


un = platform.uname()
d = "../build/lib.{0}-{1}-{2}".format(
    un[0].lower(), un[4], '.'.join(platform.python_version().split('.')[:2])
)

sys.path.insert(0, d)

class TestGetdnsMethods(unittest.TestCase):

    def test_context(self):
        c = getdns.Context()
        self.assertIsNotNone(c)
        del(c)

    def test_bogus_attribute(self):
        c = getdns.Context()
        with self.assertRaises(AttributeError):
            c.asdf
        del(c)

    def test_append_name(self):
        c = getdns.Context()
        c.append_name = getdns.APPEND_NAME_NEVER
        self.assertEqual(c.append_name, getdns.APPEND_NAME_NEVER)
        del(c)

    def test_dns_root_servers(self):
        c = getdns.Context()
        addrs = [{'address_type': 'IPv4', 'address_data': '127.0.0.254'}]
        c.dns_root_servers = addrs
        self.assertEqual(c.dns_root_servers, addrs)
        del(c)

    def test_dns_transport_list(self):
        c = getdns.Context()
        transports = [getdns.TRANSPORT_TLS,
                      getdns.TRANSPORT_UDP,
                      getdns.TRANSPORT_TCP]
        c.dns_transport_list = transports
        self.assertEqual(c.dns_transport_list, transports)
        del(c)

    def test_dnssec_allowed_skew(self):
        c = getdns.Context()
        skew = 5
        c.dnssec_allowed_skew = skew
        self.assertEqual(c.dnssec_allowed_skew, skew)
        del(c)

    def test_edns_client_subnet_private(self):
        c = getdns.Context()
        p = 1
        c.edns_client_subnet_private = p
        self.assertEqual(c.edns_client_subnet_private, p)
        del(c)

    def test_edns_do_bit(self):
        c = getdns.Context()
        do = 1
        c.edns_do_bit = do
        self.assertEqual(c.edns_do_bit, do)
        del(c)

    def test_edns_extended_rcode(self):
        c = getdns.Context()
        r = 127
        c.edns_extended_rcode = r
        self.assertEqual(c.edns_extended_rcode, r)
        del(c)

    def test_edns_maximum_udp_payload_size(self):
        c = getdns.Context()
        s = 1024
        c.edns_maximum_udp_payload_size = s
        self.assertEqual(c.edns_maximum_udp_payload_size, s)
        del(c)

    def test_edns_version(self):
        c = getdns.Context()
        v = 2
        c.edns_version = v
        self.assertEqual(c.edns_version, v)
        del(c)

    # def test_follow_redirects(self):
    #     c = getdns.Context()
    #     c.follow_redirects = getdns.REDIRECTS_DO_NOT_FOLLOW
    #     self.assertEqual(c.follow_redirects, getdns.REDIRECTS_DO_NOT_FOLLOW)
    #     del(c)

    def test_idle_timeout(self):
        c = getdns.Context()
        i = 5
        c.idle_timeout = i
        self.assertEqual(c.idle_timeout, i)
        del(c)
        
    def test_limit_outstanding_queries(self):
        c = getdns.Context()
        l = 4
        c.limit_outstanding_queries = l
        self.assertEqual(c.limit_outstanding_queries, l)
        del(c)
        del(l)

    # def test_namespaces(self):
    #     c = getdns.Context()
    #     l = [ getdns.NAMESPACE_DNS, getdns.NAMESPACE_LOCALNAMES,
    #           getdns.NAMESPACE_NETBIOS, getdns.NAMESPACE_MDNS,
    #           getdns.NAMESPACE_NIS ]
    #     random.shuffle(l)
    #     c.namespaces = l
    #     self.assertEqual(c.namespaces, l)
    #     del(c)
    #     del(l)
              
    def test_resolution_type(self):
        c = getdns.Context()
        r = getdns.RESOLUTION_STUB
        c.resolution_type = r
        self.assertEqual(c.resolution_type, r)
        del(c)
        del(r)

    def test_timeout(self):
        c = getdns.Context()
        t = 1
        c.timeout = t
        self.assertEqual(c.timeout, t)
        del(c)
        del(t)

    def test_tls_authentication(self):
        c = getdns.Context()
        t = getdns.AUTHENTICATION_NONE
        c.tls_authentication = t
        self.assertEqual(c.tls_authentication, t)
        del(c)
        del(t)

    def test_tls_query_padding_blocksize(self):
        c = getdns.Context()
        b = 512
        c.tls_query_padding_blocksize = b
        self.assertEqual(c.tls_query_padding_blocksize, b)
        del(c)
        del(b)

    def test_upstream_recursive_servers(self):
        c = getdns.Context()
        g = [
                {'address_data': '8.8.8.8', 'address_type': 'IPv4'},
                {'address_data': '8.8.4.4', 'address_type': 'IPv4'},
                {'address_data': '2001:4860:4860::8888', 'address_type': 'IPv6'},
                {'address_data': '2001:4860:4860::8844', 'address_type': 'IPv6'},
            ]
        c.upstream_recursive_servers = g
        self.assertEqual(c.upstream_recursive_servers, g)
        del(c)
        del(g)
        
    def test_advanced_upstream_recursive(self):
        c = getdns.Context()
        c.resolution_type = getdns.RESOLUTION_STUB
        u = [ { 'address_data': '185.49.141.37',
                        'address_type': 'IPv4',
                        'tsig_algorithm': 'hmac-md5.sig-alg.reg.int',
                        'tsig_name': 'hmac-md5.tsigs.getdnsapi.net',
                        'tsig_secret':  base64.b64decode('16G69OTeXW6xSQ==')
                 } ]
        c.upstream_recursive_servers = u
        f = c.general('getdnsapi.net', request_type = getdns.RRTYPE_SOA)
        self.assertEqual(f.replies_tree[0]['tsig_status'], getdns.DNSSEC_SECURE)
        del(c)
        del(u)
        del(f)        

    def test_extensions(self):
        c = getdns.Context()
        e = { 'dnssec_return_status': getdns.EXTENSION_TRUE,
              'dnssec_return_only_secure': getdns.EXTENSION_TRUE,
              'dnssec_return_validation_chain': getdns.EXTENSION_TRUE,
              'return_both_v4_and_v6': getdns.EXTENSION_TRUE,
              'add_warning_for_bad_dns': getdns.EXTENSION_TRUE,
              'return_call_reporting': getdns.EXTENSION_TRUE,
              'specify_class': getdns.RRCLASS_IN
            }
        f = c.address('www.getdnsapi.net', extensions=e)
        self.assertEqual(f.status, getdns.RESPSTATUS_GOOD)
        del(c)
        del(e)

    def test_round_robin_upstreams(self):
        c = getdns.Context()
        i = 1
        c.round_robin_upstreams = i
        self.assertEqual(c.round_robin_upstreams, i)
        del(c)

    def test_tls_backoff_time(self):
        c = getdns.Context()
        i = 6000
        c.tls_backoff_time = i
        self.assertEqual(c.round_robin_upstreams, i)
        del(c)

    def test_sync_address(self):
        c = getdns.Context()
        c.resolution_type = getdns.RESOLUTION_STUB
        r = c.address('www.getdnsapi.net')
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        self.assertTrue('185.49.141.37' in [x['address_data'] for x in
                                            r.just_address_answers])
        del(c)
        del(r)
              
    def test_sync_service(self):
        c = getdns.Context()
        c.resolution_type = getdns.RESOLUTION_STUB
        r = c.service('_xmpp-server._tcp.jabber.org')
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        del(c)
        del(r)
              
    def test_sync_hostname(self):
        c = getdns.Context()
        c.resolution_type = getdns.RESOLUTION_STUB
        r = c.hostname({'address_type': 'IPv4',
                        'address_data': '185.49.141.37'})
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        del(c)
        del(r)
        
    def test_sync_general(self):
        c = getdns.Context()
        c.resolution_type = getdns.RESOLUTION_STUB
        r = c.general('nlnetlabs.nl', request_type=getdns.RRTYPE_NS)
        self.assertEqual(r.status, getdns.RESPSTATUS_GOOD)
        del(c)
        del(r)
              
    def test_file_to_list(self):
        ns1 = {'class': 1,
               'name': 'example.com.',
               'rdata': {'nsdname': 'ns1.example.com.',
                         'rdata_raw': 'ns1.example.com.'},
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
        d = os.path.dirname(sys.argv[0])
        f = open(('.' if d == '' else d) + '/example.com.zone')
        r = getdns.file_to_list(f, 'example.com', 3600)
        self.assertIsInstance(r, list)
        self.assertEqual(r[1], ns1)
        self.assertEqual(r[2], ns2)
        f.close()
        del(f)
        del(r)
              
              
if __name__ == "__main__":
    unittest.main(verbosity=2)
