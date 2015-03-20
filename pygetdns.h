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

#ifndef PYGETDNS_H
#define PYGETDNS_H

#define PYGETDNS_VERSION "0.2.1"
#define GETDNS_DOCSTRING "getdns bindings for Python (see http://www.getdnsapi.net)"

#define GETDNS_STR_IPV4 "IPv4"
#define GETDNS_STR_IPV6 "IPv6"

#if !defined(UNUSED_PARAM)
# define UNUSED_PARAM(x) ((void)(x))
#endif

extern PyObject *getdns_error;

typedef struct pygetdns_libevent_callback_data  {
    void *userarg;
    PyObject *callback_func;
} pygetdns_libevent_callback_data;


typedef struct  {
    PyObject_HEAD
    PyObject *just_address_answers;
    PyObject *answer_type;
    PyObject *status;
    PyObject *replies_tree;
    PyObject *canonical_name;
    PyObject *replies_full;
    PyObject *validation_chain;
} getdns_ResultObject;


typedef struct  {
    PyObject *callback_func;
    char userarg[BUFSIZ];
} userarg_blob;



typedef struct {
    PyObject_HEAD
    PyObject *py_context;       /* Python capsule containing getdns_context */
    uint64_t  timeout;          /* timeout attribute (milliseconds) */
    getdns_resolution_t resolution_type; /* stub or recursive? */
    getdns_transport_t dns_transport;    /* udp/tcp/etc */
    uint16_t limit_outstanding_queries;
    getdns_redirects_t follow_redirects;
    getdns_append_name_t append_name;
    getdns_list *suffix;
    uint32_t dnssec_allowed_skew;
    uint16_t edns_maximum_udp_payload_size;
    uint8_t edns_extended_rcode;
    uint8_t edns_do_bit;
    uint8_t edns_version;
    getdns_namespace_t *namespaces;
    getdns_list *dns_root_servers;
    getdns_list *dnssec_trust_anchors;
    getdns_list *upstream_recursive_servers;
    struct event_base *event_base;
    char *implementation_string;
    char *version_string;
} getdns_ContextObject;


extern PyTypeObject getdns_ResultType;
void result_dealloc(getdns_ResultObject *self);
extern PyObject *result_getattro(PyObject *self, PyObject *nameobj);
PyObject *py_result(PyObject *result_capsule);
PyObject *result_create(struct getdns_dict *resp);

int get_status(struct getdns_dict *result_dict);
int get_answer_type(struct getdns_dict *result_dict);
char *get_canonical_name(struct getdns_dict *result_dict);
PyObject *get_just_address_answers(struct getdns_dict *result_dict);
PyObject *get_replies_tree(struct getdns_dict *result_dict);
PyObject *get_validation_chain(struct getdns_dict *result_dict);

int context_init(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_getattro(PyObject *self, PyObject *nameobj);
int context_setattro(PyObject *self, PyObject *attrname, PyObject *value);
int context_set_timeout(getdns_context *context, PyObject *py_value);
int context_set_resolution_type(getdns_context *context, PyObject *py_value);
int context_set_dns_transport(getdns_context *context, PyObject *py_value);
int context_set_limit_outstanding_queries(getdns_context *context, PyObject *py_value);
int context_set_follow_redirects(getdns_context *context, PyObject *py_value);
int context_set_append_name(getdns_context *context, PyObject *py_value);
int context_set_suffix(getdns_context *context, PyObject *py_value);
int context_set_dnssec_allowed_skew(getdns_context *context, PyObject *py_value);
int context_set_edns_maximum_udp_payload_size(getdns_context *context, PyObject *py_value);
int context_set_edns_extended_rcode(getdns_context *context, PyObject *py_value);
int context_set_edns_version(getdns_context *context, PyObject *py_value);
int context_set_namespaces(getdns_context *context, PyObject *py_value);
int context_set_dns_root_servers(getdns_context *context, PyObject *py_value);
int context_set_dnssec_trust_anchors(getdns_context *context, PyObject *py_value);
int context_set_upstream_recursive_servers(getdns_context *context, PyObject *py_value);
int context_set_edns_do_bit(getdns_context *context, PyObject *py_value);

PyObject *context_get_api_information(getdns_ContextObject *self, PyObject *unused);
PyObject *context_general(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_address(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_hostname(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_service(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_run(getdns_ContextObject *self, PyObject *args, PyObject *keywds);
PyObject *context_cancel_callback(getdns_ContextObject *self, PyObject *args, PyObject *keywds);

void context_dealloc(getdns_ContextObject *self);
PyObject *get_callback(char *py_main, char *callback);
void callback_shim(struct getdns_context *context, getdns_callback_type_t type,
                   struct getdns_dict *response, void *userarg, getdns_transaction_t tid);

int result_init(getdns_ResultObject *self, PyObject *args, PyObject *keywds);
PyObject *result_getattro(PyObject *self, PyObject *nameobj);
int result_setattro(PyObject *self, PyObject *attrname, PyObject *value);

PyObject *pythonify_address_list(getdns_list *list);
PyObject *glist_to_plist(struct getdns_list *list);
PyObject *gdict_to_pdict(struct getdns_dict *dict);
PyObject *convertBinData(getdns_bindata* data, const char* key);
struct getdns_dict *extensions_to_getdnsdict(PyDictObject *);
PyObject *decode_getdns_response(struct getdns_dict *);
PyObject *decode_getdns_replies_tree_response(struct getdns_dict *response);
PyObject *getFullResponse(struct getdns_dict *dict);
getdns_dict *getdnsify_addressdict(PyObject *pydict);


#endif /* PYGETDNS_H */
