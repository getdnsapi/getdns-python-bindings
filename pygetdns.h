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

static PyObject *getdns_error;
struct getdns_dict *extensions_to_getdnsdict(PyDictObject *);
PyObject *decode_getdns_response(struct getdns_dict *);
PyObject *decode_getdns_replies_tree_response(struct getdns_dict *response);
PyObject *getFullResponse(struct getdns_dict *dict);
char *reverse_address(struct getdns_bindata *address_data);
PyObject *context_fd(PyObject *self, PyObject *args, PyObject *keywds);
PyObject *context_get_num_pending_requests(PyObject *self, PyObject *args, PyObject *keywds);
PyObject *context_process_async(PyObject *self, PyObject *args, PyObject *keywds);

typedef struct pygetdns_libevent_callback_data  {
    char *callback_func;
    void *userarg;
} pygetdns_libevent_callback_data;
