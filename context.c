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

#include <Python.h>
#include <getdns/getdns.h>
#include <arpa/inet.h>
#include "pygetdns.h"

int
context_init(getdns_ContextObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "set_from_os",
        0
    };
    struct getdns_context *context = 0;
    int  set_from_os = 1;       /* default to True */
    getdns_return_t ret;
    char err_buf[256];          
    PyObject *py_context;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|i", kwlist,
                                     &set_from_os))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((set_from_os > 1) || (set_from_os < 0))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_create(&context, set_from_os)) != GETDNS_RETURN_GOOD)  {
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(PyExc_AttributeError, err_buf);
        return -1;
    }
    py_context = PyCapsule_New(context, "context", 0);
    Py_INCREF(py_context);
    self->py_context = py_context;
    return 0;
}


void
context_dealloc(getdns_ContextObject *self)
{
    getdns_context *context;

    if ((context = PyCapsule_GetPointer(self->py_context, "context")) == NULL)  {
        return;
    }
    Py_XDECREF(self->py_context);
    getdns_context_destroy(context);
    return;
}


int
context_set_timeout(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint64_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_timeout(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_resolution_type(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint64_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if (!((value == GETDNS_RESOLUTION_RECURSING) || (value == GETDNS_RESOLUTION_STUB)))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_resolution_type(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_dns_transport(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint64_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if (!((value == GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP) ||
          (value == GETDNS_TRANSPORT_UDP_ONLY)) ||
          (value == GETDNS_TRANSPORT_TCP_ONLY)  ||
          (value == GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_dns_transport(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}
                                   

int
context_set_limit_outstanding_queries(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint16_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_limit_outstanding_queries(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_follow_redirects(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint64_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if (!((value == GETDNS_REDIRECTS_FOLLOW) || (value == GETDNS_REDIRECTS_DO_NOT_FOLLOW)))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_follow_redirects(context, (getdns_redirects_t)value)) !=
        GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_append_name(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint64_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if (!((value == GETDNS_APPEND_NAME_ALWAYS) ||
          (value == GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE) ||
          (value == GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE) ||
          (value == GETDNS_APPEND_NAME_NEVER)))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_append_name(context, (getdns_append_name_t)value)) !=
        GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_dnssec_allowed_skew(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint32_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_dnssec_allowed_skew(context, (uint32_t)value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_edns_maximum_udp_payload_size(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint32_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_edns_maximum_udp_payload_size(context, (uint16_t)value))
        != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_edns_extended_rcode(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint8_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = (uint8_t)PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_edns_extended_rcode(context, (uint8_t)value))
        != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_edns_version(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    uint8_t value;
    
    if (!PyInt_Check(py_value))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((value = (uint8_t)PyInt_AsLong(py_value)) < 0)  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((ret = getdns_context_set_edns_version(context, (uint8_t)value))
        != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_namespaces(getdns_context *context, PyObject *py_value)
{
    size_t count;
    getdns_namespace_t *namespaces;
    getdns_return_t ret;
    int i;

    if (!PyList_Check(py_value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((count = (int)PyList_Size(py_value)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((namespaces = malloc(sizeof(getdns_namespace_t) * count)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_MEMORY_ERROR_TEXT);
        return -1;
    }
    for (i = 0 ; i < count ; i++)  {
        namespaces[i] = (getdns_namespace_t)PyInt_AsLong(PyList_GetItem(py_value, (Py_ssize_t)i));
        if ((namespaces[i] < GETDNS_NAMESPACE_DNS) || (namespaces[i] > GETDNS_NAMESPACE_NIS))  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return -1;
        }
    }
    if ((ret = getdns_context_set_namespaces(context, count, namespaces)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}        


int
context_set_dns_root_servers(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    getdns_list *addresses;
    Py_ssize_t len;
    int i;
    PyObject *an_address;
    PyObject *str;
    getdns_dict *addr_dict;
    int domain;
    unsigned char buf[sizeof(struct in6_addr)];

    if (!PyList_Check(py_value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    len = PyList_Size(py_value);
    addresses = getdns_list_create();
    for (i = 0 ; i < len ; i++)  {
        getdns_bindata addr_data;
        getdns_bindata addr_type;

        if ((an_address = PyList_GetItem(py_value, (Py_ssize_t)i)) != NULL)  {
            if (PyDict_Size(an_address) != 2)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            addr_dict = getdns_dict_create();
            if ((str = PyDict_GetItemString(an_address, "address_type")) == NULL)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            if (!PyString_Check(str))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            addr_type.data = (uint8_t *)strdup(PyString_AsString(str));
            addr_type.size = strlen((char *)addr_type.data);
            if (strlen((char *)addr_type.data) != 4)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_WRONG_TYPE_REQUESTED_TEXT);
                return -1;
            }
            if (!strncasecmp((char *)addr_type.data, "IPv4", 4))
                domain = AF_INET;
            else if (!strncasecmp((char *)addr_type.data, "IPv6", 4))
                domain = AF_INET6;
            else  {
                PyErr_SetString(getdns_error,  GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            getdns_dict_set_bindata(addr_dict, "address_type", &addr_type);

            if ((str = PyDict_GetItemString(an_address, "address_data")) == NULL)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            if (!PyString_Check(str))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            if (inet_pton(domain, PyString_AsString(str), buf) <= 0)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            addr_data.data = (uint8_t *)buf;
            addr_data.size = (domain == AF_INET ? 4 : 16);
            getdns_dict_set_bindata(addr_dict, "address_data", &addr_data);
            getdns_list_set_dict(addresses, (size_t)i, addr_dict);
        }
    }
    if ((ret = getdns_context_set_dns_root_servers(context, addresses)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}
            

int
context_set_dnssec_trust_anchors(getdns_context *context, PyObject *py_value)
{
    getdns_return_t ret;
    getdns_list *addresses;
    Py_ssize_t len;
    int i;
    PyObject *an_address;

    if (!PyList_Check(py_value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    len = PyList_Size(py_value);
    addresses = getdns_list_create();
    for (i = 0 ; i < len ; i++)  {
        getdns_bindata *value = 0;

        if ((an_address = PyList_GetItem(py_value, (Py_ssize_t)i)) != NULL)  {
            if (!PyString_Check(an_address))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            value->data = (uint8_t *)strdup(PyString_AsString(py_value));
            value->size = strlen((char *)value->data);
            getdns_list_set_bindata(addresses, (size_t)i, value);
        }  else  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return -1;
        }
    }
    if ((ret = getdns_context_set_dnssec_trust_anchors(context, addresses)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;
}


int
context_set_upstream_recursive_servers(getdns_context *context, PyObject *py_value)
{
    int  len;
    PyObject *py_upstream;
    struct getdns_list *upstream_list;
    int  i;
    getdns_return_t ret;

    if (!PyList_Check(py_value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if ((len = (int)PyList_Size(py_value)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
        
    upstream_list = getdns_list_create();
    for (i = 0 ; i < len ; i++)  {
        getdns_dict *a_upstream;

        if ((py_upstream = PyList_GetItem(py_value, (Py_ssize_t)i)) != NULL)  {
            if ((a_upstream = getdnsify_addressdict(py_upstream)) == NULL)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
            if (getdns_list_set_dict(upstream_list, i, a_upstream) != GETDNS_RETURN_GOOD)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return -1;
            }
        }  else  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return -1;
        }
    }
    if ((ret = getdns_context_set_upstream_recursive_servers(context, upstream_list)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return -1;
    }
    return 0;

}


PyObject *
context_getattro(PyObject *self, PyObject *nameobj)
{
    getdns_ContextObject *myself = (getdns_ContextObject *)self;
    struct getdns_context *context;
    getdns_dict *api_info;
    getdns_dict *all_context;
    getdns_return_t ret;
    char *attrname;

    attrname = PyString_AsString(nameobj);
    context = PyCapsule_GetPointer(myself->py_context, "context");
    api_info = getdns_context_get_api_information(context);
    if (!strncmp(attrname, "resolution_type", strlen("resolution_type")))  {
        uint32_t resolution_type;
        if ((ret = getdns_dict_get_int(api_info, "resolver_type", &resolution_type)) != GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong((long)resolution_type);
    }
    if ((ret = getdns_dict_get_dict(api_info, "all_context", &all_context)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    if (!strncmp(attrname, "timeout", strlen("timeout")))  {
        uint32_t timeout;
        if ((ret = getdns_dict_get_int(all_context, "timeout", &timeout)) != GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyLong_FromLong((long)timeout);
    }
    if (!strncmp(attrname, "dns_transport", strlen("dns_transport")))  {
        uint32_t dns_transport;
        if ((ret = getdns_dict_get_int(all_context, "dns_transport", &dns_transport)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
    }
    if (!strncmp(attrname, "limit_outstanding_queries", strlen("limit_outstanding_queries")))  {
        uint32_t limit_outstanding_queries;
        if ((ret = getdns_dict_get_int(all_context, "limit_outstanding_queries",
                                       &limit_outstanding_queries)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong(limit_outstanding_queries);
    }
    if (!strncmp(attrname, "follow_redirects", strlen("follow_redirects")))  {
        uint32_t follow_redirects;
        if ((ret = getdns_dict_get_int(all_context, "follow_redirects",
                                       &follow_redirects)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong(follow_redirects);
    }
    if (!strncmp(attrname, "append_name", strlen("append_name")))  {
        uint32_t append_name;
        if ((ret = getdns_dict_get_int(all_context, "append_name",
                                       &append_name)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong(append_name);
    }
    if (!strncmp(attrname, "dnssec_allowed_skew", strlen("dnssec_allowed_skew")))  {
        uint32_t dnssec_allowed_skew;
        if ((ret = getdns_dict_get_int(all_context, "dnssec_allowed_skew", &dnssec_allowed_skew)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong((long)dnssec_allowed_skew);
    }
    if (!strncmp(attrname, "edns_maximum_udp_payload_size", strlen("edns_maximum_udp_payload_size")))  {
        uint32_t edns_maximum_udp_payload_size;
        if ((ret = getdns_dict_get_int(all_context, "edns_maximum_udp_payload_size",
                                       &edns_maximum_udp_payload_size)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong((long)edns_maximum_udp_payload_size);
    }
    if (!strncmp(attrname, "edns_extended_rcode", strlen("edns_extended_rcode")))  {
        uint32_t edns_extended_rcode;
        if ((ret = getdns_dict_get_int(all_context, "edns_extended_rcode",
                                       &edns_extended_rcode)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong((long)edns_extended_rcode);
    }
    if (!strncmp(attrname, "edns_version", strlen("edns_version")))  {
        uint32_t edns_version;
        if ((ret = getdns_dict_get_int(all_context, "edns_version",
                                       &edns_version)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        return PyInt_FromLong((long)edns_version);
    }
    if (!strncmp(attrname, "namespaces", strlen("namespaces")))  {
        PyObject *py_namespaces;
        getdns_list *namespaces;
        getdns_return_t ret;
        if ((ret = getdns_dict_get_list(all_context, "namespaces",
                                        &namespaces)) != GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        if ((py_namespaces = glist_to_plist(namespaces)) == NULL)  
            PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return py_namespaces;
    }
#if 0
    if (!strncmp(attrname, "dns_root_servers", strlen("dns_root_servers")))  {
        PyObject *py_rootservers;
        getdns_list *dns_root_servers;
        getdns_return_t ret;
        if ((ret = getdns_dict_get_list(all_context, "dns_root_servers", &dns_root_servers)) !=
            GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        if ((py_rootservers = glist_to_plist(dns_root_servers)) == NULL)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        }
        return py_rootservers;
    }
#endif
    if (!strncmp(attrname, "upstream_recursive_servers", strlen("upstream_recursive_servers")))  {
        PyObject *py_upstream_servers;
        getdns_list *upstream_list;
        getdns_return_t ret;

        if ((ret = getdns_dict_get_list(all_context, "upstream_recursive_servers",
                                        &upstream_list)) != GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
#if 0
        if ((py_upstream_servers = glist_to_plist(upstream_list)) == NULL)  {
#endif 
        if ((py_upstream_servers = pythonify_address_list(upstream_list)) == NULL)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
            return NULL;
        }
        return py_upstream_servers;
    }

    return PyObject_GenericGetAttr((PyObject *)self, nameobj);
}



int
context_setattro(PyObject *self, PyObject *attrname, PyObject *py_value)
{
    getdns_ContextObject *myself = (getdns_ContextObject *)self;
    struct getdns_context *context;
    char *name;

    name = PyString_AsString(attrname);
    if ((context = PyCapsule_GetPointer(myself->py_context, "context")) == NULL)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return -1;
    }
    if (!strncmp(name, "timeout", strlen("timeout")))  {
        return(context_set_timeout(context, py_value));
    }
    if (!strncmp(name, "resolution_type", strlen("resolution_type")))  {
        return(context_set_resolution_type(context, py_value));
    }
    if (!strncmp(name, "limit_outstanding_queries", strlen("limit_outstanding_queries")))  {
        return(context_set_limit_outstanding_queries(context, py_value));
    }
    if (!strncmp(name, "follow_redirects", strlen("follow_redirects")))  {
        return(context_set_follow_redirects(context, py_value));
    }
    if (!strncmp(name, "append_name", strlen("append_name")))  {
        return(context_set_append_name(context, py_value));
    }
    if (!strncmp(name, "dnssec_allowed_skew", strlen("dnssec_allowed_skew")))  {
        return(context_set_dnssec_allowed_skew(context, py_value));
    }
    if (!strncmp(name, "edns_maximum_udp_payload_size", strlen("edns_maximum_udp_payload_size")))  {
        return(context_set_edns_maximum_udp_payload_size(context, py_value));
    }
    if (!strncmp(name, "edns_extended_rcode", strlen("edns_extended_rcode")))  {
        return(context_set_edns_extended_rcode(context, py_value));
    }
    if (!strncmp(name, "edns_version", strlen("edns_version")))  {
        return(context_set_edns_version(context, py_value));
    }
    if (!strncmp(name, "namespaces", strlen("namespaces")))  {
        return(context_set_namespaces(context, py_value));
    }
    if (!strncmp(name, "dns_root_servers", strlen("dns_root_servers")))  {
        return(context_set_dns_root_servers(context, py_value));
    }
    if (!strncmp(name, "upstream_recursive_servers", strlen("upstream_recursive_servers")))  {
        return(context_set_upstream_recursive_servers(context, py_value));
    }
        
    return 0;
}


PyObject *
context_general(getdns_ContextObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "name",
        "request_type",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };
    getdns_context *context;
    char *name;
    uint16_t  request_type;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid = 0;
    char *callback = 0;
    PyObject *resp;

    if ((context = PyCapsule_GetPointer(self->py_context, "context")) == NULL)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sH|Osls", kwlist,
                                     &name, &request_type,
                                     &extensions_obj, &userarg, &tid, &callback))  {
        return NULL;
    }
    if ((resp = do_query(self->py_context, name, request_type, extensions_obj, userarg,
                           (long)tid, callback)) == 0)  {
        PyObject *err_type, *err_value, *err_traceback;
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }
    return resp;
}


PyObject *
context_address(getdns_ContextObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "name",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };
    getdns_context *context;
    char *name;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid;
    char * callback = 0;
    PyObject *resp;

    if ((context = PyCapsule_GetPointer(self->py_context, "context")) == NULL)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|OsHs", kwlist,
                                     &name, 
                                     &extensions_obj, &userarg, &tid, &callback))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
    }
    if ((resp = do_query(self->py_context, name, GETDNS_RRTYPE_A, extensions_obj, userarg,
                           tid, callback)) == 0)  {
        PyObject *err_type, *err_value, *err_traceback;
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }
    return resp;
}


PyObject *
context_hostname(getdns_ContextObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "address",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };
    void *address;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid;
    char * callback = 0;
    PyObject *resp;
    getdns_context *context;

    if ((context = PyCapsule_GetPointer(self->py_context, "context")) == NULL)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "O|Osls", kwlist,
                                     &address, 
                                     &extensions_obj, &userarg, &tid, &callback))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL; 
    }
    if ((resp = do_query(self->py_context, address, GETDNS_RRTYPE_PTR, extensions_obj, userarg,
                           tid, callback)) == 0)  {
        PyObject *err_type, *err_value, *err_traceback;
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }
    return resp;
}


PyObject *
context_service(getdns_ContextObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "name",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };
    char *name;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid;
    char *callback = 0;
    PyObject *resp;
    getdns_context *context;

    if ((context = PyCapsule_GetPointer(self->py_context, "context")) == NULL)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|Osls", kwlist,
                                     &name, 
                                     &extensions_obj, &userarg, &tid, &callback))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;            
    }
    if ((resp = do_query(self->py_context, name, (uint16_t)GETDNS_RRTYPE_SRV, extensions_obj, userarg,
                           tid, callback)) == 0)  {
        PyObject *err_type, *err_value, *err_traceback;
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_Restore(err_type, err_value, err_traceback);
        return NULL;
    }
    return resp;
}


PyObject *
context_get_api_information(getdns_ContextObject *self, PyObject *unused)
{
    getdns_context *context;
    getdns_dict *api_info;
    PyObject *py_api;
    getdns_bindata *version_string;
    getdns_bindata *imp_string;
    uint32_t resolver_type;
    getdns_dict *all_context;
    PyObject *py_all_context;
    size_t ncontexts;
    getdns_list *context_names;
    getdns_bindata *a_name;
    uint32_t context_value;
    getdns_return_t ret;
    int i;



    if ((context = PyCapsule_GetPointer(self->py_context, "context")) == NULL)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    py_api = PyDict_New();
    api_info = getdns_context_get_api_information(context);
    if ((ret = getdns_dict_get_bindata(api_info, "version_string", &version_string)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    if (PyDict_SetItemString(py_api, "version_string", PyString_FromString((char *)version_string->data)))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    if ((ret = getdns_dict_get_bindata(api_info, "implementation_string", &imp_string)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    if (PyDict_SetItemString(py_api, "implementation_string", PyString_FromString((char *)imp_string->data)))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    if ((ret = getdns_dict_get_int(api_info, "resolver_type", &resolver_type)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    if (PyDict_SetItemString(py_api, "resolver_type", PyInt_FromLong((long)resolver_type)))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    if ((ret = getdns_dict_get_dict(api_info, "all_context", &all_context)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    if ((ret = getdns_dict_get_names(all_context, &context_names)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    if ((ret = getdns_list_get_length(context_names, &ncontexts)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    py_all_context = PyDict_New();
    for ( i = 0 ; i < ncontexts ; i++ )  {
        if ((ret = getdns_list_get_bindata(context_names, (size_t)i, &a_name)) != GETDNS_RETURN_GOOD)  {
            char err_buf[256];
            getdns_strerror(ret, err_buf, sizeof err_buf);
            PyErr_SetString(getdns_error, err_buf);
            return NULL;
        }
        if (!strncmp((char *)a_name->data, "namespaces", strlen("namespaces")))  {
            getdns_list *namespaces = getdns_list_create();
            PyObject *py_namespaces;
            size_t n_spaces;
            uint32_t space;
            int j;

            if ((ret = getdns_dict_get_list(all_context, (char *)a_name->data, &namespaces)) != GETDNS_RETURN_GOOD)  {
                char err_buf[256];
                getdns_strerror(ret, err_buf, sizeof err_buf);
                PyErr_SetString(getdns_error, err_buf);
                return NULL;
            }
            (void)getdns_list_get_length(namespaces, &n_spaces);
            py_namespaces = PyList_New((Py_ssize_t)n_spaces);
            for ( j = 0 ; j < n_spaces ; j++ )  {
                (void)getdns_list_get_int(namespaces, j, &space);
                PyList_SetItem(py_namespaces, (Py_ssize_t)j, PyInt_FromLong((long)space));
            }
            PyDict_SetItemString(py_all_context, "namespaces", py_namespaces);
        } else if (!strncmp((char *)a_name->data, "suffix", strlen("suffix")))  {
            getdns_list *suffixes = getdns_list_create();
            PyObject *py_suffixes;
            size_t n_suffixes;
            getdns_bindata *suffix;
            int j;

            if ((ret = getdns_dict_get_list(all_context, (char *)a_name->data, &suffixes)) != GETDNS_RETURN_GOOD)  {
                char err_buf[256];
                getdns_strerror(ret, err_buf, sizeof err_buf);
                PyErr_SetString(getdns_error, err_buf);
                return NULL;
            }
            (void)getdns_list_get_length(suffixes, &n_suffixes);
            py_suffixes = PyList_New((Py_ssize_t)n_suffixes);
            for ( j = 0 ; j < n_suffixes ; j++ )  {
                (void)getdns_list_get_bindata(suffixes, j, &suffix);
                PyList_SetItem(py_suffixes, (Py_ssize_t)j, PyString_FromString((char *)suffix->data));
            }
            PyDict_SetItemString(py_all_context, "suffix", py_suffixes);
        } else if (!strncmp((char *)a_name->data, "upstream_recursive_servers",
                            strlen("upstream_recursive_servers")))  {
            getdns_list *upstream_list;
            PyObject *py_upstream_list;
            PyObject *py_upstream;
            size_t n_upstreams;
            getdns_dict *upstream;
            getdns_bindata *upstream_data;
            getdns_bindata *upstream_type;
            char *paddr_buf[256];
            int domain;
            int j;

            if ((ret = getdns_dict_get_list(all_context, (char *)a_name->data, &upstream_list)) != GETDNS_RETURN_GOOD)  {
                char err_buf[256];
                getdns_strerror(ret, err_buf, sizeof err_buf);
                PyErr_SetString(getdns_error, err_buf);
                return NULL;
            }
            (void)getdns_list_get_length(upstream_list, &n_upstreams);
            py_upstream_list = PyList_New((Py_ssize_t)n_upstreams);
            for ( j = 0 ; j < n_upstreams ; j++ )  {
                (void)getdns_list_get_dict(upstream_list, j, &upstream);
                (void)getdns_dict_get_bindata(upstream, "address_data", &upstream_data);
                (void)getdns_dict_get_bindata(upstream, "address_type", &upstream_type);
                if (!strncasecmp((char *)upstream_type->data, "IPv4", 4))  
                    domain = AF_INET;
                else if (!strncasecmp((char *)upstream_type->data, "IPv6", 6))  
                    domain = AF_INET6;
                else  {
                    PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
                    return NULL;
                }
                py_upstream = PyDict_New();
                PyDict_SetItemString(py_upstream, "address_data",
                                     PyString_FromString(inet_ntop(domain, (void *)upstream_data->data, (char *)paddr_buf, 256)));
                PyDict_SetItemString(py_upstream, "address_type", PyString_FromString((domain == AF_INET ? "IPv4" : "IPv6")));
                PyList_SetItem(py_upstream_list, j, py_upstream);
            }
            PyDict_SetItemString(py_all_context, (char *)a_name->data, py_upstream_list);
        }  else  {            
            if ((ret = getdns_dict_get_int(all_context, (char *)a_name->data, &context_value)) != GETDNS_RETURN_GOOD)  {
                char err_buf[256];
                getdns_strerror(ret, err_buf, sizeof err_buf);
                PyErr_SetString(getdns_error, err_buf);
                return NULL;
            }
            PyDict_SetItemString(py_all_context, (char *)a_name->data, PyInt_FromLong((long)context_value));
        }
        PyDict_SetItemString(py_api, "all_context", py_all_context);
    }    
    return(py_api);
}        
