/**
 *
 * \file getdns.c
 * @brief pygetdns core functions and classes
 *
 */


/*
 * Copyright (c) 2014, Verisign, Inc.
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
#include <structmember.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include <getdns/getdns_ext_libevent.h>
#include <event2/event.h>
#include <pthread.h>
#include "pygetdns.h"



PyMethodDef Context_methods[] = {
    { "get_api_information", (PyCFunction)context_get_api_information,
      METH_NOARGS, "Return context settings" },
    { "general", (PyCFunction)context_general, METH_VARARGS|METH_KEYWORDS,
      "method for looking up any type of DNS record" },
    { "address", (PyCFunction)context_address, METH_VARARGS|METH_KEYWORDS,
      "method for looking up an address given a host name" },
    { "hostname", (PyCFunction)context_hostname, METH_VARARGS|METH_KEYWORDS,
      "method for looking up a host name given an IP address" },
    { "service", (PyCFunction)context_service, METH_VARARGS|METH_KEYWORDS,
      "method for looking up relevant SRV record for a name" },
    { NULL }
};

PyMemberDef Context_members[] = {
    { "timeout", T_INT, offsetof(getdns_ContextObject, timeout), 0, "timeout in milliseconds" },
    { "resolution_type", T_INT, offsetof(getdns_ContextObject, resolution_type), 0,
      "lookup as recursive or stub resolver" },
    { "dns_transport", T_INT, offsetof(getdns_ContextObject, dns_transport),
      0, "dns transport" },
    { "limit_outstanding_queries", T_INT, offsetof(getdns_ContextObject, limit_outstanding_queries),
      0, "limit on the number of unanswered queries" },
    { "follow_redirects", T_INT, offsetof(getdns_ContextObject, follow_redirects),
      0, "follow redirects" },
    { "append_name", T_INT, offsetof(getdns_ContextObject, append_name),
      0, "append a suffix to the query string before resolving name" },
    { "dnssec_allowed_skew", T_INT, offsetof(getdns_ContextObject, dnssec_allowed_skew), 0,
      "number of seconds of skew allowed when checking RRSIG Expiration and Inception fields" },
    { "edns_maximum_udp_payload_size", T_INT, offsetof(getdns_ContextObject, edns_maximum_udp_payload_size),
      0, "edns maximum udp payload size" },
    { "edns_extended_rcode", T_INT, offsetof(getdns_ContextObject, edns_extended_rcode),
      0, "edns extended rcode" },
    { "edns_do_bit", T_INT, offsetof(getdns_ContextObject, edns_do_bit),
      0, "edns do bit" },
    { "edns_version", T_INT, offsetof(getdns_ContextObject, edns_version), 0, "edns version" },
    { "namespaces", T_OBJECT, offsetof(getdns_ContextObject, namespaces), 0,
      "ordered list of namespaces to be queried" },
    { "dns_root_servers", T_OBJECT, offsetof(getdns_ContextObject, dns_root_servers), 0,
      "list of dictionaries of root servers" },
    { "dnssec_trust_anchors", T_OBJECT, offsetof(getdns_ContextObject, dnssec_trust_anchors), 0,
      "list of trust anchors" },
    { "suffix", T_OBJECT, offsetof(getdns_ContextObject, suffix), 0, "list of strings to be appended to search strings" },
    { "upstream_recursive_servers", T_OBJECT, offsetof(getdns_ContextObject,
                                                       upstream_recursive_servers), 0,
      "list of dictionaries defining where a stub resolver will send queries" },
    { "implementation_string", T_STRING|READONLY, offsetof(getdns_ContextObject, implementation_string), 0,
      "string set by the implementer" },
    { "version_string", T_STRING|READONLY, offsetof(getdns_ContextObject, version_string), 0,
      "string set by the implementer" },
    { NULL }
};

PyGetSetDef Context_getseters[] = {
    { "timeout", (getter)NULL, (setter)context_set_timeout, "set timeout", NULL },
    { "resolution_type", (getter)NULL, (setter)context_set_resolution_type, "set resolution type", NULL },
    { NULL }
};

PyTypeObject getdns_ContextType = {
    PyObject_HEAD_INIT(NULL)
    0,
    "getdns.Context",
    sizeof(getdns_ContextObject),
    0,                         /*tp_itemsize*/
    (destructor)context_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    context_getattro,          /*tp_getattro*/
    context_setattro,          /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
    "Context object",          /* tp_doc */
    0,                         /* tp_traverse       */
    0,                         /* tp_clear          */
    0,                         /* tp_richcompare    */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter           */
    0,                         /* tp_iternext       */
    Context_methods,           /* tp_methods        */
    Context_members,           /* tp_members        */
    Context_getseters,         /* tp_getset         */
    0,                         /* tp_base           */
    0,                         /* tp_dict           */
    0,                         /* tp_descr_get      */
    0,                         /* tp_descr_set      */
    0,                         /* tp_dictoffset     */
    (initproc)context_init,    /* tp_init           */
};


/*
 *  A shim to sit between the event callback function
 *  and the python callback.  This is a wee bit hacky
 */


void         
callback_shim(getdns_context *context, getdns_callback_type_t type, getdns_dict *resp,
  void *u, getdns_transaction_t tid)
{
    pygetdns_libevent_callback_data *callback_data;
    PyObject *response;
    PyObject *getdns_runner;
    PyGILState_STATE state;

    callback_data = (pygetdns_libevent_callback_data *)u;
    getdns_runner = callback_data->callback_func;
    if (!PyCallable_Check(getdns_runner))  { /* XXX */
        printf("callback not runnable\n");
        return;
    }
    if ((response = getFullResponse(resp)) == 0)  {
        PyErr_SetString(getdns_error, "Unable to decode response");
        return;
        /* need to throw exceptiion XXX */
    }
    /* Python callback prototype: */
    /* callback(context, callback_type, response, userarg, tid) */
    state = PyGILState_Ensure();
    PyObject_CallFunction(getdns_runner, "OHOsi", context, type, response,
                          callback_data->userarg, (int)tid);
    PyGILState_Release(state);
}


void 
destroy_context(PyObject *context_capsule)
{
    struct getdns_context *context = 0;

    context = PyCapsule_GetPointer(context_capsule, "context");
    getdns_context_destroy(context);
    Py_DECREF(context_capsule);
}


/**
 * create context, return context dict
 */

static PyObject *
context_create(PyObject *self, PyObject *args, PyObject *keywds)
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
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;    
    }
    if ((ret = getdns_context_create(&context, set_from_os)) != GETDNS_RETURN_GOOD)  {
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }

    py_context = PyCapsule_New(context, "context", destroy_context);
    Py_INCREF(py_context);
    return py_context;
}


/*
 * called from pthread_create.  Pull out the query arguments,
 * get the Python callback function from the dictionary for
 * __main__
 */

void
marshall_query(pygetdns_async_args_blob *blob)
{
    PyObject *ret;

    if ((ret = dispatch_query(blob->context_capsule, blob->name,
                              blob->type, blob->extensions, blob->userarg, blob->tid,
                              blob->callback)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        pthread_exit(0);
    }
}
                              


PyObject *
dispatch_query(PyObject *context_capsule,
         void *name,
         uint16_t request_type,
         PyDictObject *extensions_obj,
         void *userarg,
         int tid,
         char *callback)

{
    struct getdns_context *context;
    struct getdns_dict *extensions_dict = 0;
    struct getdns_dict *resp = 0;
    getdns_return_t ret;
    char *query_name;

    context = PyCapsule_GetPointer(context_capsule, "context");
    if (extensions_obj)  {
        if ((extensions_dict = extensions_to_getdnsdict(extensions_obj)) == 0)  {
            PyErr_SetString(getdns_error, "Dictionary parse failure");
            return NULL;
        }
    }
    if (request_type == GETDNS_RRTYPE_PTR)  {
        PyObject *address = (PyObject *)name;
        getdns_dict *addr_dict;
        getdns_bindata addr_data;
        getdns_bindata addr_type;
        PyObject *str;
        int domain;
        unsigned char buf[sizeof(struct in6_addr)];

        if (!PyDict_Check(address))  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;    
        }
        if (PyDict_Size(address) != 2)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;    
        }
        addr_dict = getdns_dict_create();
        if ((str = PyDict_GetItemString(address, "address_type")) == NULL)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;    
        }
        if (!PyString_Check(str))  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
        addr_type.data = (uint8_t *)strdup(PyString_AsString(str));
        addr_type.size = strlen((char *)addr_type.data);
        if (strlen((char *)addr_type.data) != 4)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_WRONG_TYPE_REQUESTED_TEXT);
            return NULL;
        }
        if (!strncasecmp((char *)addr_type.data, "IPv4", 4))
            domain = AF_INET;
        else if (!strncasecmp((char *)addr_type.data, "IPv6", 4))
            domain = AF_INET6;
        else  {
            PyErr_SetString(getdns_error,  GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
        getdns_dict_set_bindata(addr_dict, "address_type", &addr_type);

        if ((str = PyDict_GetItemString(address, "address_data")) == NULL)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;            
        }
        if (!PyString_Check(str))  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
        if (inet_pton(domain, PyString_AsString(str), buf) <= 0)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
        addr_data.data = (uint8_t *)buf;
        addr_data.size = (domain == AF_INET ? 4 : 16);
        getdns_dict_set_bindata(addr_dict, "address_data", &addr_data);
        if ((query_name = reverse_address(&addr_data)) == NULL)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
    }  else
        query_name = (char *)name;

    if (callback)  {
        struct event_base *gen_event_base;
        int dispatch_ret;
        pygetdns_libevent_callback_data *callback_data = userarg;

        if ((gen_event_base = event_base_new()) == NULL)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
            return NULL;
        }
        
        if ((ret = getdns_extension_set_libevent_base(context, gen_event_base)) != GETDNS_RETURN_GOOD)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
            return NULL;
        }

        if ((ret = getdns_general(context, query_name, request_type,
                                  extensions_dict, (void *)callback_data,
                                  (getdns_transaction_t *)&tid, callback_shim)) != GETDNS_RETURN_GOOD)  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
            event_base_free(gen_event_base);
            return NULL;
        }
        dispatch_ret = event_base_dispatch(gen_event_base);
        UNUSED_PARAM(dispatch_ret);
            
        event_base_free(gen_event_base);
        return Py_None;
    }
    if ((ret = getdns_general_sync(context, query_name, request_type,
                                   extensions_dict, &resp)) != GETDNS_RETURN_GOOD)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    return getFullResponse(resp);
    
}


/*
 * there's not many people doing this so it probably
 * bears some explanation.  If there's a callback argument
 * we need to spin off a thread to handle the callback,
 * and do it in a way that doesn't make the Python thread
 * scheduler barf.  Additionally, in order to avoid making
 * getdns barf, we need to move data off the stack and onto
 * the heap for it to be available to the new thread.  This includes
 * a pointer to the PyObject representing the user-defined
 * callback function.
 * So basically we're encapsulating the data so that the
 * new thread can use it to recreate the calling environment
 */


PyObject *
do_query(PyObject *context_capsule,
         void *name,
         uint16_t request_type,
         PyDictObject *extensions_obj,
         void *userarg,
         long tid,
         char *callback)

{
    if (!callback)  {
        return dispatch_query(context_capsule, name, request_type, extensions_obj,
                       userarg, tid, callback);
    }  else  {
        PyObject *main_module;
        PyObject *main_dict;
        PyObject *getdns_runner;
        pthread_t runner_thread;
        pygetdns_async_args_blob *async_blob;
        char *u;

        if ((main_module = PyImport_AddModule("__main__")) == 0)  {
            PyErr_SetString(getdns_error, "No __main__");
            /* need to throw an error here */
        }
        main_dict = PyModule_GetDict(main_module);
        if ((getdns_runner = PyDict_GetItemString(main_dict, callback)) == 0)  {
            PyErr_SetString(getdns_error, "callback not found");
            return NULL;
        }

        async_blob = (pygetdns_async_args_blob *)malloc(sizeof(pygetdns_async_args_blob));
        async_blob->context_capsule = context_capsule;
        async_blob->name = malloc(256); /* XXX magic number */
        strncpy(async_blob->name, name, strlen(name)+1);
        async_blob->type = request_type;
        async_blob->extensions = extensions_obj;
        async_blob->userarg = (pygetdns_libevent_callback_data *)malloc(sizeof(pygetdns_libevent_callback_data));
        u = malloc(1024);
        strncpy(u, userarg, strlen(userarg)+1);
        async_blob->userarg->userarg = u;
        async_blob->tid = tid;
        async_blob->callback = malloc(256); /* XXX magic number */
        strncpy(async_blob->callback, callback, strlen(callback));
        async_blob->runner = getdns_runner;
        async_blob->userarg->callback_func = getdns_runner;
        Py_BEGIN_ALLOW_THREADS;
        pthread_create(&runner_thread, NULL, (void *)marshall_query, (void *)async_blob);
        pthread_detach(runner_thread);
        Py_END_ALLOW_THREADS;
        return Py_None;
    }
}


static PyObject *
cancel_callback(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "transaction_id",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    getdns_return_t ret;
    long tid;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Ol", kwlist,
                                     &context_capsule, &tid))  {
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_cancel_callback(context, (getdns_transaction_t)tid)) !=
        GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}


static PyObject *
general(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "name",
        "request_type",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };

    PyObject *context_capsule;
    char *name;
    uint16_t  request_type;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid = 0;
    char *callback = 0;
    PyObject *my_ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OsH|Osls", kwlist,
                                     &context_capsule, &name, &request_type,
                                     &extensions_obj, &userarg, &tid, &callback))  {
        return NULL;
    }
    if ((my_ret = do_query(context_capsule, name, request_type, extensions_obj, userarg,
                           (long)tid, callback)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    return my_ret;
}


static PyObject *
service(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "name",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };
    PyObject *context_capsule;
    char *name;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid;
    char *callback = 0;
    PyObject *my_ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Os|Osls", kwlist,
                                     &context_capsule, &name, 
                                     &extensions_obj, &userarg, &tid, &callback))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;            
    }
    if ((my_ret = do_query(context_capsule, name, (uint16_t)GETDNS_RRTYPE_SRV, extensions_obj, userarg,
                           tid, callback)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    return my_ret;

    
}


static PyObject *
address(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "name",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };
    PyObject *context_capsule;
    char *name;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid;
    char * callback = 0;
    PyObject *my_ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Os|OsHs", kwlist,
                                     &context_capsule, &name, 
                                     &extensions_obj, &userarg, &tid, &callback))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
    }
    if ((my_ret = do_query(context_capsule, name, GETDNS_RRTYPE_A, extensions_obj, userarg,
                           tid, callback)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    return my_ret;
}

static PyObject *
hostname(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "address",
        "extensions",
        "userarg",
        "transaction_id",
        "callback",
        0
    };
    PyObject *context_capsule;
    void *address;
    PyDictObject *extensions_obj = 0;
    void *userarg;
    long tid;
    char * callback = 0;
    PyObject *my_ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OO|Osls", kwlist,
                                     &context_capsule, &address, 
                                     &extensions_obj, &userarg, &tid, &callback))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL; 
    }
    if ((my_ret = do_query(context_capsule, address, GETDNS_RRTYPE_PTR, extensions_obj, userarg,
                           tid, callback)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    return my_ret;
}

static PyObject *
ctx_set_resolution_type(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    getdns_resolution_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Oi", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if ((value != GETDNS_RESOLUTION_RECURSING) && (value != GETDNS_RESOLUTION_STUB))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_resolution_type(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}


static PyObject *
ctx_set_namespaces(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "count",
        "namespaces",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    size_t count;
    PyObject *namespace_blob;
    getdns_namespace_t *namespaces;
    getdns_return_t ret;
    int i;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OlO", kwlist,
                                     &context_capsule, &count, &namespace_blob))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if (!PyList_Check(namespace_blob))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;            
    }
    if ((namespaces = malloc(sizeof(getdns_namespace_t) * count)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_MEMORY_ERROR_TEXT);
        return NULL;
    }
    for (i = 0 ; i < count ; i++)  {
        namespaces[i] = (getdns_namespace_t)PyInt_AsLong(PyList_GetItem(namespace_blob, (Py_ssize_t)i));
        if ((namespaces[i] < GETDNS_NAMESPACE_DNS) || (namespaces[i] > GETDNS_NAMESPACE_NIS))  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
    }
    if ((ret = getdns_context_set_namespaces(context, count, namespaces)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        


static PyObject *
ctx_set_dns_transport(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    getdns_transport_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Oi", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((value < GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP) ||
        (value > GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if ((ret = getdns_context_set_dns_transport(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        



static PyObject *
ctx_set_limit_outstanding_queries(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "limit",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    uint16_t limit;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Oi", kwlist,
                                     &context_capsule, &limit))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_limit_outstanding_queries(context, limit)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        

static PyObject *
ctx_set_timeout(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "timeout",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    uint64_t timeout;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OL", kwlist,
                                     &context_capsule, &timeout))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_timeout(context, timeout)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        


PyObject *
ctx_set_follow_redirects(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    getdns_redirects_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Oi", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_follow_redirects(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        

static PyObject *
ctx_set_dns_root_servers(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "addresses",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    PyObject *py_address_list;
    getdns_list *addresses;
    getdns_dict *addr_dict;
    getdns_return_t ret;
    int i;
    Py_ssize_t len;
    unsigned char buf[sizeof(struct in6_addr)];
    PyObject *an_address;
    PyObject *str;
    int domain;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OO", kwlist,
                                     &context_capsule, &py_address_list))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if (!PyList_Check(py_address_list))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;            
    }
    len = PyList_Size(py_address_list);
    addresses = getdns_list_create();
    for (i = 0 ; i < len ; i++)  {
        getdns_bindata addr_data;
        getdns_bindata addr_type;

        if ((an_address = PyList_GetItem(py_address_list, (Py_ssize_t)i)) != NULL)  {
            if (PyDict_Size(an_address) != 2)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;    
            }
            addr_dict = getdns_dict_create();
            if ((str = PyDict_GetItemString(an_address, "address_type")) == NULL)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;    
            }
            if (!PyString_Check(str))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
            }
            addr_type.data = (uint8_t *)strdup(PyString_AsString(str));
            addr_type.size = strlen((char *)addr_type.data);
            if (strlen((char *)addr_type.data) != 4)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_WRONG_TYPE_REQUESTED_TEXT);
                return NULL;
            }
            if (!strncasecmp((char *)addr_type.data, "IPv4", 4))
                domain = AF_INET;
            else if (!strncasecmp((char *)addr_type.data, "IPv6", 4))
                domain = AF_INET6;
            else  {
                PyErr_SetString(getdns_error,  GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
            }
            getdns_dict_set_bindata(addr_dict, "address_type", &addr_type);

            if ((str = PyDict_GetItemString(an_address, "address_data")) == NULL)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;            
            }
            if (!PyString_Check(str))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
            }
            if (inet_pton(domain, PyString_AsString(str), buf) <= 0)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
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
        return NULL;
    }
    return Py_None;
}        


PyObject *
ctx_set_append_name(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    getdns_context *context;
    getdns_append_name_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OO", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((value < GETDNS_APPEND_NAME_ALWAYS) || (value > GETDNS_APPEND_NAME_NEVER))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if ((ret = getdns_context_set_append_name(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        


static PyObject *
ctx_set_suffix(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };

    PyObject *context_capsule;
    struct getdns_context *context;
    PyObject *py_value_list;
    getdns_list *values;
    getdns_return_t ret;
    Py_ssize_t len;
    PyObject *a_value;
    int i;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OO", kwlist,
                                     &context_capsule, &py_value_list))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    len = PyList_Size(py_value_list);
    values = getdns_list_create();
    for (i = 0 ; i < len ; i++)  {
        getdns_bindata *value = 0;

        if ((a_value = PyList_GetItem(py_value_list, (Py_ssize_t)i)) != NULL)  {
            if (!PyString_Check(a_value))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
            }
            value->data = (uint8_t *)strdup(PyString_AsString(a_value));
            value->size = strlen((char *)value->data);
            getdns_list_set_bindata(values, (size_t)i, value);
        }  else  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
    }
    if ((ret = getdns_context_set_suffix(context, values)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}


static PyObject *
ctx_set_dnssec_trust_anchors(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    PyObject *py_value_list;
    getdns_list *values;
    getdns_return_t ret;
    Py_ssize_t len;
    PyObject *a_value;
    int i;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OO", kwlist,
                                     &context_capsule, &py_value_list))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    len = PyList_Size(py_value_list);
    values = getdns_list_create();
    for (i = 0 ; i < len ; i++)  {
        getdns_bindata *value = 0;

        if ((a_value = PyList_GetItem(py_value_list, (Py_ssize_t)i)) != NULL)  {
            if (!PyString_Check(a_value))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
            }
            value->data = (uint8_t *)strdup(PyString_AsString(a_value));
            value->size = strlen((char *)value->data);
            getdns_list_set_bindata(values, (size_t)i, value);
        }  else  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
    }
    if ((ret = getdns_context_set_dnssec_trust_anchors(context, values)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}


static PyObject *
ctx_set_dnssec_allowed_skew(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    uint32_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "Oi", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_dnssec_allowed_skew(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        



static PyObject *
ctx_set_edns_maximum_udp_payload_size(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    uint16_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OH", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((value < 512) || (value > 65535))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if ((ret = getdns_context_set_edns_maximum_udp_payload_size(context, value)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        



static PyObject *
ctx_set_edns_extended_rcode(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    uint16_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OH", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if (value > 255)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_edns_extended_rcode(context, ((uint8_t)(value & 0xff)))) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        


static PyObject *
ctx_set_edns_version(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    uint16_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OH", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if (value > 255)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_edns_version(context, ((uint8_t)(value & 0xff)))) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        


static PyObject *
ctx_set_edns_do_bit(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "value",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    uint16_t value;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OH", kwlist,
                                     &context_capsule, &value))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if (value > 1)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_set_edns_version(context, ((uint8_t)(value & 0xff)))) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}        


static PyObject *
ctx_set_upstream_recursive_servers(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "upstream_list",
        0
    };
    PyObject *context_capsule;
    struct getdns_context *context;
    PyObject *py_upstream_list;
    int  len;
    PyObject *py_upstream;
    struct getdns_list *upstream_list;
    int  i;
    getdns_return_t ret;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OO", kwlist,
                                     &context_capsule, &py_upstream_list))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if (!PyList_Check(py_upstream_list))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if ((len = (int)PyList_Size(py_upstream_list)) == 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
        
    upstream_list = getdns_list_create();
    for (i = 0 ; i < len ; i++)  {
        getdns_dict *a_upstream;

        if ((py_upstream = PyList_GetItem(py_upstream_list, (Py_ssize_t)i)) != NULL)  {
            if ((a_upstream = getdnsify_addressdict(py_upstream)) == NULL)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
            }
            if (getdns_list_set_dict(upstream_list, i, a_upstream) != GETDNS_RETURN_GOOD)  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
                return NULL;
            }
        }  else  {
            PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
            return NULL;
        }
    }
    if ((ret = getdns_context_set_upstream_recursive_servers(context, upstream_list)) != GETDNS_RETURN_GOOD)  {
        char err_buf[256];
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;

}


static PyObject *
ctx_get_api_information(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        0
    };
    PyObject *context_capsule;
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

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "O", kwlist,
                                     &context_capsule))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
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
        } else if (!strncmp((char *)a_name->data, "upstream_recursive_servers", strlen("upstream_recursive_servers")))  {
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




static struct PyMethodDef getdns_methods[] = {
    { "context_create", (PyCFunction)context_create, METH_KEYWORDS },
    { "general", (PyCFunction)general, METH_KEYWORDS },
    { "address", (PyCFunction)address, METH_KEYWORDS },
    { "service", (PyCFunction)service, METH_KEYWORDS },
    { "hostname", (PyCFunction)hostname, METH_KEYWORDS },
    { "cancel_callback", (PyCFunction)cancel_callback, METH_KEYWORDS },
    { "context_set_namespaces", (PyCFunction)ctx_set_namespaces, METH_KEYWORDS },
    { "context_set_resolution_type", (PyCFunction)ctx_set_resolution_type, METH_KEYWORDS },
    { "context_set_dns_transport", (PyCFunction)ctx_set_dns_transport, METH_KEYWORDS },
    { "context_set_limit_outstanding_queries", (PyCFunction)ctx_set_limit_outstanding_queries, METH_KEYWORDS },
    { "context_set_timeout", (PyCFunction)ctx_set_timeout, METH_KEYWORDS },
    { "context_set_follow_redirects", (PyCFunction)ctx_set_follow_redirects, METH_KEYWORDS },
    { "context_set_dns_root_servers", (PyCFunction)ctx_set_dns_root_servers, METH_KEYWORDS },
    { "context_set_append_name", (PyCFunction)ctx_set_append_name, METH_KEYWORDS },
    { "context_set_suffix", (PyCFunction)ctx_set_suffix, METH_KEYWORDS },
    { "context_set_dnssec_trust_anchors", (PyCFunction)ctx_set_dnssec_trust_anchors, METH_KEYWORDS },
    { "context_set_dnssec_allowed_skew", (PyCFunction)ctx_set_dnssec_allowed_skew, METH_KEYWORDS },
    { "context_set_edns_maximum_udp_payload_size", (PyCFunction)ctx_set_edns_maximum_udp_payload_size, METH_KEYWORDS },
    { "context_set_edns_extended_rcode", (PyCFunction)ctx_set_edns_extended_rcode, METH_KEYWORDS },
    { "context_set_edns_version", (PyCFunction)ctx_set_edns_version, METH_KEYWORDS },
    { "context_set_edns_do_bit", (PyCFunction)ctx_set_edns_do_bit, METH_KEYWORDS },
    { "context_get_api_information", (PyCFunction)ctx_get_api_information, METH_KEYWORDS },
    { "context_fd", (PyCFunction)context_fd, METH_KEYWORDS },
    { "context_get_num_pending_requests", (PyCFunction)context_get_num_pending_requests, METH_KEYWORDS },
    { "context_set_upstream_recursive_servers", (PyCFunction)ctx_set_upstream_recursive_servers, METH_KEYWORDS },
    { "context_process_async", (PyCFunction)context_process_async, METH_KEYWORDS },
    { 0, 0, 0 }
};


PyMODINIT_FUNC
initgetdns(void)
{
    PyObject *g;

    Py_Initialize();
    PyEval_InitThreads();
    if ((g = Py_InitModule("getdns", getdns_methods)) == NULL)
        return;
    getdns_error = PyErr_NewException("getdns.error", NULL, NULL);
    Py_INCREF(getdns_error);
    PyModule_AddObject(g, "error", getdns_error);
    getdns_ContextType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&getdns_ContextType) < 0)
        return;
    Py_INCREF(&getdns_ContextType);
    PyModule_AddObject(g, "Context", (PyObject *)&getdns_ContextType);
/*
 * return value constants
 */

    PyModule_AddIntConstant(g, "GETDNS_RETURN_GOOD", 0);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_GENERIC_ERROR", 1);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_BAD_DOMAIN_NAME", 300);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_BAD_CONTEXT", 301);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_CONTEXT_UPDATE_FAIL", 302);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_UNKNOWN_TRANSACTION", 303);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_NO_SUCH_LIST_ITEM", 304);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_NO_SUCH_DICT_NAME", 305);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_WRONG_TYPE_REQUESTED", 306);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_NO_SUCH_EXTENSION", 307);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_EXTENSION_MISFORMAT", 308);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED", 309);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_MEMORY_ERROR", 310);
    PyModule_AddIntConstant(g, "GETDNS_RETURN_INVALID_PARAMETER", 311);

/*
 * dnssec values
 */

    PyModule_AddIntConstant(g, "GETDNS_DNSSEC_SECURE", 400);
    PyModule_AddIntConstant(g, "GETDNS_DNSSEC_BOGUS", 401);
    PyModule_AddIntConstant(g, "GETDNS_DNSSEC_INDETERMINATE", 402);
    PyModule_AddIntConstant(g, "GETDNS_DNSSEC_INSECURE", 403);
    PyModule_AddIntConstant(g, "GETDNS_DNSSEC_NOT_PERFORMED", 404);

/*
 * namespace types
 */

    PyModule_AddIntConstant(g, "GETDNS_NAMESPACE_DNS", 500);
    PyModule_AddIntConstant(g, "GETDNS_NAMESPACE_LOCALNAMES", 501);
    PyModule_AddIntConstant(g, "GETDNS_NAMESPACE_NETBIOS", 502);
    PyModule_AddIntConstant(g, "GETDNS_NAMESPACE_MDNS", 503);
    PyModule_AddIntConstant(g, "GETDNS_NAMESPACE_NIS", 504);

/*
 * resolution types
 */

    PyModule_AddIntConstant(g, "GETDNS_RESOLUTION_STUB", 520);
    PyModule_AddIntConstant(g, "GETDNS_RESOLUTION_RECURSING", 521);

/*
 * redirect policies
 */

    PyModule_AddIntConstant(g, "GETDNS_REDIRECTS_FOLLOW", 530);
    PyModule_AddIntConstant(g, "GETDNS_REDIRECTS_DO_NOT_FOLLOW", 531);

/*
 * transport arrangements
 */

    PyModule_AddIntConstant(g, "GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP", 540);
    PyModule_AddIntConstant(g, "GETDNS_TRANSPORT_UDP_ONLY", 541);
    PyModule_AddIntConstant(g, "GETDNS_TRANSPORT_TCP_ONLY", 542);
    PyModule_AddIntConstant(g, "GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN", 543);

/*
 * suffix appending methods
 */

    PyModule_AddIntConstant(g, "GETDNS_APPEND_NAME_ALWAYS", 550);
    PyModule_AddIntConstant(g, "GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE", 551);
    PyModule_AddIntConstant(g, "GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE", 552);
    PyModule_AddIntConstant(g, "GETDNS_APPEND_NAME_NEVER", 553);

/*
 * context codes
 */
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_NAMESPACES", 600);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_RESOLUTION_TYPE", 601);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_FOLLOW_REDIRECTS", 602);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS", 603);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_DNS_ROOT_SERVERS", 604);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_DNS_TRANSPORT", 605);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES", 606);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_APPEND_NAME", 607);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_SUFFIX", 608);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_DNSSEC_TRUST_ANCHORS", 609);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE", 610);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_EDNS_EXTENDED_RCODE", 611);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_EDNS_VERSION", 612);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_EDNS_DO_BIT", 613);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_DNSSEC_ALLOWED_SKEW", 614);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_MEMORY_FUNCTIONS", 615);
    PyModule_AddIntConstant(g, "GETDNS_CONTEXT_CODE_TIMEOUT", 61);

/*
 * name service types
 */

    PyModule_AddIntConstant(g, "GETDNS_NAMETYPE_DNS", 800);
    PyModule_AddIntConstant(g, "GETDNS_NAMETYPE_WINS", 801);

    PyModule_AddIntConstant(g, "GETDNS_EXTENSION_TRUE", 1000);
    PyModule_AddIntConstant(g, "GETDNS_EXTENSION_FALSE", 1001);

    PyModule_AddIntConstant(g, "GETDNS_CALLBACK_COMPLETE", 700);
    PyModule_AddIntConstant(g, "GETDNS_CALLBACK_CANCEL", 701);
    PyModule_AddIntConstant(g, "GETDNS_CALLBACK_TIMEOUT", 702);
    PyModule_AddIntConstant(g, "GETDNS_CALLBACK_ERROR", 703);

    PyModule_AddIntConstant(g, "GETDNS_RESPSTATUS_GOOD", 900);
    PyModule_AddIntConstant(g, "GETDNS_RESPSTATUS_NO_NAME", 901);
    PyModule_AddIntConstant(g, "GETDNS_RESPSTATUS_ALL_TIMEOUT", 902);
    PyModule_AddIntConstant(g, "GETDNS_RESPSTATUS_NO_SECURE_ANSWERS", 903);

    PyModule_AddIntConstant(g, "GETDNS_BAD_DNS_CNAME_IN_TARGET", 1100);
    PyModule_AddIntConstant(g, "GETDNS_BAD_DNS_ALL_NUMERIC_LABEL", 1101);
    PyModule_AddIntConstant(g, "GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE", 1102);

/*
 * rr type constants
 */

    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_A", 1);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NS", 2);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MD", 3);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MF", 4);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_CNAME", 5);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_SOA", 6);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MB", 7);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MG", 8);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MR", 9);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NULL", 10);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_WKS", 11);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_PTR", 12);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_HINFO", 13);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MINFO", 14);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MX", 15);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_TXT", 16);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_RP", 17);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_AFSDB", 18);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_X25", 19);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_ISDN", 20);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_RT", 21);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NSAP", 22);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_SIG", 24);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_KEY", 25);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_PX", 26);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_GPOS", 27);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_AAAA", 28);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_LOC", 29);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NXT", 30);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_EID", 31);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NIMLOC", 32);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_SRV", 33);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_ATMA", 34);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NAPTR", 35);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_KX", 36);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_CERT", 37);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_A6", 38);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_DNAME", 39);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_SINK", 40);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_OPT", 41);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_APL", 42);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_DS", 43);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_SSHFP", 44);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_IPSECKEY", 45);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_RRSIG", 46);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NSEC", 47);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_DNSKEY", 48);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_DHCID", 49);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NSEC3", 50);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NSEC3PARAM", 51);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_TLSA", 52);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_HIP", 55);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NINFO", 56);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_RKEY", 57);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_TALINK", 58);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_CDS", 59);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_SPF", 99);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_UINFO", 100);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_UID", 101);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_GID", 102);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_UNSPEC", 103);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_NID", 104);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_L32", 105);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_L64", 106);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_LP", 107);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_EUI48", 108);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_EUI64", 109);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_TKEY", 249);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_TSIG", 250);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_IXFR", 251);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_AXFR", 252);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MAILB", 253);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_MAILA", 254);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_URI", 256);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_CAA", 257);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_TA", 32768);
    PyModule_AddIntConstant(g, "GETDNS_RRTYPE_DLV", 32769);

}
