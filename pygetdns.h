/**
 * defines, declarations, and globals for pygetdns
 */

/*
 * Copyright (c) 2014, Versign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Include. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#define GETDNS_STR_IPV4 "IPv4"
#define GETDNS_STR_IPV6 "IPv6"

#if !defined(UNUSED_PARAM)
# define UNUSED_PARAM(x) ((void)(x))
#endif

static PyObject *getdns_error;

typedef struct pygetdns_libevent_callback_data  {
    char *callback_func;
    void *userarg;
} pygetdns_libevent_callback_data;


typedef struct {
    PyObject_HEAD
    PyObject *py_context;       /* Python capsule containing getdns_context */
    uint64_t  timeout;          /* timeout attribute (milliseconds) */
    getdns_resolution_t resolution_type; /* stub or recursive? */
    getdns_transport_t dns_transport;    /* udp/tcp/etc */
    uint16_t limit_outstanding_queries;
    getdns_redirects_t follow_redirects;
    getdns_append_name_t append_name;
    uint32_t dnssec_allowed_skew;
    uint16_t edns_maximum_udp_payload_size;
    uint8_t edns_extended_rcode;
    uint8_t edns_version;
    getdns_namespace_t *namespaces;
    getdns_list *dns_root_servers;
    getdns_list *dnssec_trust_anchors;
    getdns_list *upstream_recursive_servers;
} getdns_ContextObject;


int context_init(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_getattro(PyObject *self, PyObject *nameobj);
int context_setattro(PyObject *self, PyObject *attrname, PyObject *value);
int context_set_timeout(getdns_context *context, PyObject *py_value);
int context_set_resolution_type(getdns_context *context, PyObject *py_value);
int context_set_dns_transport(getdns_context *context, PyObject *py_value);
int context_set_limit_outstanding_queries(getdns_context *context, PyObject *py_value);
int context_set_follow_redirects(getdns_context *context, PyObject *py_value);
int context_set_append_name(getdns_context *context, PyObject *py_value);
int context_set_dnssec_allowed_skew(getdns_context *context, PyObject *py_value);
int context_set_edns_maximum_udp_payload_size(getdns_context *context, PyObject *py_value);
int context_set_edns_extended_rcode(getdns_context *context, PyObject *py_value);
int context_set_edns_version(getdns_context *context, PyObject *py_value);
int context_set_namespaces(getdns_context *context, PyObject *py_value);
int context_set_dns_root_servers(getdns_context *context, PyObject *py_value);
int context_set_dnssec_trust_anchors(getdns_context *context, PyObject *py_value);
int context_set_upstream_recursive_servers(getdns_context *context, PyObject *py_value);

PyObject *context_get_api_information(getdns_ContextObject *self, PyObject *unused);
PyObject *context_general(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_address(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_hostname(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_service(getdns_ContextObject *self, PyObject *args, PyObject *keywds);

PyObject *do_query(PyObject *context_capsule, void *name, uint16_t request_type,
                   PyDictObject *extensions_obj, void *userarg, long tid, char *callback);
PyObject *pythonify_address_list(getdns_list *list);
PyObject *glist_to_plist(struct getdns_list *list);
PyObject *gdict_to_pdict(struct getdns_dict *dict);
PyObject *convertBinData(getdns_bindata* data, const char* key);
struct getdns_dict *extensions_to_getdnsdict(PyDictObject *);
PyObject *decode_getdns_response(struct getdns_dict *);
PyObject *decode_getdns_replies_tree_response(struct getdns_dict *response);
PyObject *getFullResponse(struct getdns_dict *dict);
char *reverse_address(struct getdns_bindata *address_data);
PyObject *context_fd(PyObject *self, PyObject *args, PyObject *keywds);
PyObject *context_get_num_pending_requests(PyObject *self, PyObject *args, PyObject *keywds);
PyObject *context_process_async(PyObject *self, PyObject *args, PyObject *keywds);
getdns_dict *getdnsify_addressdict(PyObject *pydict);
void context_dealloc(getdns_ContextObject *self);
