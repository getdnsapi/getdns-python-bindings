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
#include <getdns/getdns_extra.h>
#include <event2/event.h>
#include <datetime.h>
#include <time.h>
#include "pygetdns.h"


PyObject *getdns_error;

static PyObject *get_errorstr_by_id(PyObject *self, PyObject *args, PyObject *keywds);
static PyObject *root_trust_anchor(PyObject *self, PyObject *args, PyObject *keywds);
static void add_getdns_constants(PyObject *g);

static struct PyMethodDef getdns_methods[] = {
    { "get_errorstr_by_id", (PyCFunction)get_errorstr_by_id,
      METH_VARARGS|METH_KEYWORDS, "return getdns error text by error id" },
    { "root_trust_anchor", (PyCFunction)root_trust_anchor, METH_NOARGS,
      "retrieve default list of trust anchor records used to validate DNSSEC" },
    { 0, 0, 0 }
};


#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef getdnsdef = {
    PyModuleDef_HEAD_INIT,
    "getdns",     /* m_name */
    GETDNS_DOCSTRING,    /* m_doc */
    -1,                  /* m_size */
    getdns_methods,      /* m_methods */
    NULL,                /* m_reload */
    NULL,                /* m_traverse */
    NULL,                /* m_clear */
    NULL,                /* m_free */

};
#endif

PyMemberDef Result_members[] = {
    { "just_address_answers", T_OBJECT_EX, offsetof(getdns_ResultObject, just_address_answers),
      READONLY, "Only the query answers" },
    { "replies_tree", T_OBJECT_EX, offsetof(getdns_ResultObject, replies_tree),
      READONLY, "The replies tree dictionary" },
    { "replies_full", T_OBJECT_EX, offsetof(getdns_ResultObject, replies_full),
      READONLY, "The entire replies structure returned by getdns" },
    { "status", T_OBJECT_EX, offsetof(getdns_ResultObject, status), READONLY,
      "Response status" },
    { "answer_type", T_OBJECT_EX, offsetof(getdns_ResultObject, answer_type), READONLY, "Answer type" },
    { "canonical_name", T_OBJECT_EX, offsetof(getdns_ResultObject, canonical_name), READONLY,
      "Canonical name" },
    { "validation_chain", T_OBJECT_EX, offsetof(getdns_ResultObject, validation_chain),
      READONLY, "DNSSEC certificate chain" },
    { NULL },
};

static PyMethodDef Result_methods[] = {
    { NULL },
};


PyTypeObject getdns_ResultType = {
#if PY_MAJOR_VERSION >= 3
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
#endif
    "getdns.Result",           /*tp_name*/
    sizeof(getdns_ResultObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)result_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    result_str,                /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    result_str,                /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Result objects",          /* tp_doc */
    0,               /* tp_traverse */
    0,               /* tp_clear */
    0,               /* tp_richcompare */
    0,               /* tp_weaklistoffset */
    0,               /* tp_iter */
    0,               /* tp_iternext */
    Result_methods,             /* tp_methods */
    Result_members,             /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)result_init,      /* tp_init */
    0,                         /* tp_alloc */
    PyType_GenericNew,                 /* tp_new */
};


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
    { "run", (PyCFunction)context_run, METH_VARARGS|METH_KEYWORDS,
      "run unprocessed events" },
    { "cancel_callback", (PyCFunction)context_cancel_callback, METH_VARARGS|METH_KEYWORDS,
      "cancel outstanding callbacks" },
    { NULL }
};

PyMemberDef Context_members[] = {
    { "timeout", T_INT, offsetof(getdns_ContextObject, timeout), 0, "timeout in milliseconds" },
    { "resolution_type", T_INT, offsetof(getdns_ContextObject, resolution_type), 0,
      "lookup as recursive or stub resolver" },
    { "dns_transport_list", T_OBJECT, offsetof(getdns_ContextObject, dns_transport_list), 0, 
      "ordered list of dns transports" },
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
    { "suffix", T_OBJECT, offsetof(getdns_ContextObject, suffix), 0,
      "list of strings to be appended to search strings" },
    { "upstream_recursive_servers", T_OBJECT, offsetof(getdns_ContextObject,
                                                       upstream_recursive_servers), 0,
      "list of dictionaries defining where a stub resolver will send queries" },
    { "implementation_string", T_STRING|READONLY, offsetof(getdns_ContextObject, implementation_string), 0,
      "string set by the implementer" },
    { "version_string", T_STRING|READONLY, offsetof(getdns_ContextObject, version_string), 0,
      "string set by the implementer" },
    {"idle_timeout", T_INT, offsetof(getdns_ContextObject, idle_timeout), 0, "TCP idle timeout" },
    {"tls_authentication", T_INT, offsetof(getdns_ContextObject, tls_authentication), 0,
     "TLS authentication basis" },
    {"tls_query_padding_blocksize", T_INT, offsetof(getdns_ContextObject, tls_query_padding_blocksize),
     0, "padding blocksize" },
    { NULL }
};


PyTypeObject getdns_ContextType = {
#if PY_MAJOR_VERSION >= 3
    PyVarObject_HEAD_INIT(NULL, 0)
#else
    PyObject_HEAD_INIT(NULL)
    0,
#endif
    "getdns.Context",
    sizeof(getdns_ContextObject),
    0,                         /*tp_itemsize*/
    (destructor)context_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /*tp_compare*/
    context_str,               /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    context_str,                         /*tp_str*/
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
    0,                         /* tp_getset         */
    0,                         /* tp_base           */
    0,                         /* tp_dict           */
    0,                         /* tp_descr_get      */
    0,                         /* tp_descr_set      */
    0,                         /* tp_dictoffset     */
    (initproc)context_init,    /* tp_init           */
};


static PyObject *
get_errorstr_by_id(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = { "id",
                            NULL };
    int id;
    char *errstr;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &id))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if ((errstr = (char *)getdns_get_errorstr_by_id((uint16_t)id)) == 0) 
        return Py_None;
    else
#if PY_MAJOR_VERSION >= 3
        return PyUnicode_FromString(errstr);
#else
        return PyString_FromString(errstr);
#endif
}


static PyObject *
root_trust_anchor(PyObject *self, PyObject *args, PyObject *keywds)
{
    getdns_list *trust_anchors;
    time_t anchors_date;
    struct tm *but;             /* busted out time */
    PyObject *pdate;
    PyObject *ta_tuple;

    PyDateTime_IMPORT;
    if ((trust_anchors = getdns_root_trust_anchor(&anchors_date)) == NULL)
        Py_RETURN_NONE;
    but = gmtime(&anchors_date);
    pdate = PyDateTime_FromDateAndTime(but->tm_year+1900, but->tm_mon+1, but->tm_mday,
                                       but->tm_hour, but->tm_min, but->tm_sec, 0);
    ta_tuple = PyTuple_Pack(2, glist_to_plist(trust_anchors), pdate);
    Py_INCREF(ta_tuple);
    return ta_tuple;
}


#if PY_MAJOR_VERSION >= 3

PyMODINIT_FUNC
PyInit_getdns(void)
{
    PyObject *g;                /* the getdns module object */

    Py_Initialize();
    if ((g = PyModule_Create(&getdnsdef)) == NULL)  {
        PyErr_SetString(PyExc_ImportError, "Unable to initialize getdns");
        return NULL;
    }
    getdns_error = PyErr_NewException("getdns.error", NULL, NULL);
    Py_INCREF(getdns_error);
    PyModule_AddObject(g, "error", getdns_error);
    getdns_ContextType.tp_new = PyType_GenericNew;
    getdns_ResultType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&getdns_ResultType) < 0)  {
        PyErr_SetString(PyExc_ImportError, "Unable to initialize getdns");
        return NULL;
    }
    Py_INCREF(&getdns_ResultType);
    PyModule_AddObject(g, "Result", (PyObject *)&getdns_ResultType);
    if (PyType_Ready(&getdns_ContextType) < 0)  {
        PyErr_SetString(PyExc_ImportError, "Unable to initialize getdns");
        return NULL;
    }
    Py_INCREF(&getdns_ContextType);
    PyModule_AddObject(g, "Context", (PyObject *)&getdns_ContextType);
    PyModule_AddStringConstant(g, "__version__", PYGETDNS_VERSION);
    add_getdns_constants(g);
    return g;
}
    

#else
        
PyMODINIT_FUNC
initgetdns(void)
{
    PyObject *g;

    Py_Initialize();
    if ((g = Py_InitModule3("getdns", getdns_methods, GETDNS_DOCSTRING)) == NULL)
        return;
    getdns_error = PyErr_NewException("getdns.error", NULL, NULL);
    Py_INCREF(getdns_error);
    PyModule_AddObject(g, "error", getdns_error);
    getdns_ContextType.tp_new = PyType_GenericNew;
    getdns_ResultType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&getdns_ResultType) < 0)  
        return;
    Py_INCREF(&getdns_ResultType);
    PyModule_AddObject(g, "Result", (PyObject *)&getdns_ResultType);
    if (PyType_Ready(&getdns_ContextType) < 0)
        return;
    Py_INCREF(&getdns_ContextType);
    PyModule_AddObject(g, "Context", (PyObject *)&getdns_ContextType);
    PyModule_AddStringConstant(g, "__version__", PYGETDNS_VERSION);
    add_getdns_constants(g);
}

#endif

    
static void
add_getdns_constants(PyObject *g)
{
/*
 * return value constants
 */

    PyModule_AddIntConstant(g, "RETURN_GOOD", 0);
    PyModule_AddIntConstant(g, "RETURN_GENERIC_ERROR", 1);
    PyModule_AddIntConstant(g, "RETURN_BAD_DOMAIN_NAME", 300);
    PyModule_AddIntConstant(g, "RETURN_BAD_CONTEXT", 301);
    PyModule_AddIntConstant(g, "RETURN_CONTEXT_UPDATE_FAIL", 302);
    PyModule_AddIntConstant(g, "RETURN_UNKNOWN_TRANSACTION", 303);
    PyModule_AddIntConstant(g, "RETURN_NO_SUCH_LIST_ITEM", 304);
    PyModule_AddIntConstant(g, "RETURN_NO_SUCH_DICT_NAME", 305);
    PyModule_AddIntConstant(g, "RETURN_WRONG_TYPE_REQUESTED", 306);
    PyModule_AddIntConstant(g, "RETURN_NO_SUCH_EXTENSION", 307);
    PyModule_AddIntConstant(g, "RETURN_EXTENSION_MISFORMAT", 308);
    PyModule_AddIntConstant(g, "RETURN_DNSSEC_WITH_STUB_DISALLOWED", 309);
    PyModule_AddIntConstant(g, "RETURN_MEMORY_ERROR", 310);
    PyModule_AddIntConstant(g, "RETURN_INVALID_PARAMETER", 311);
    PyModule_AddIntConstant(g, "RETURN_NOT_IMPLEMENTED", 312);

/*
 * dnssec values
 */

    PyModule_AddIntConstant(g, "DNSSEC_SECURE", 400);
    PyModule_AddIntConstant(g, "DNSSEC_BOGUS", 401);
    PyModule_AddIntConstant(g, "DNSSEC_INDETERMINATE", 402);
    PyModule_AddIntConstant(g, "DNSSEC_INSECURE", 403);
    PyModule_AddIntConstant(g, "DNSSEC_NOT_PERFORMED", 404);

/*
 * namespace types
 */


    PyModule_AddIntConstant(g, "NAMESPACE_DNS", 500);
    PyModule_AddIntConstant(g, "NAMESPACE_LOCALNAMES", 501);
    PyModule_AddIntConstant(g, "NAMESPACE_NETBIOS", 502);
    PyModule_AddIntConstant(g, "NAMESPACE_MDNS", 503);
    PyModule_AddIntConstant(g, "NAMESPACE_NIS", 504);

/*
 * resolution types
 */

    PyModule_AddIntConstant(g, "RESOLUTION_STUB", 520);
    PyModule_AddIntConstant(g, "RESOLUTION_RECURSING", 521);

/*
 * redirect policies
 */

    PyModule_AddIntConstant(g, "REDIRECTS_FOLLOW", 530);
    PyModule_AddIntConstant(g, "REDIRECTS_DO_NOT_FOLLOW", 531);

/*
 * transport arrangements
 */

    PyModule_AddIntConstant(g, "TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP", 540);
    PyModule_AddIntConstant(g, "TRANSPORT_UDP_ONLY", 541);
    PyModule_AddIntConstant(g, "TRANSPORT_TCP_ONLY", 542);
    PyModule_AddIntConstant(g, "TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN", 543);

/*
 * transport list constants
 */

    PyModule_AddIntConstant(g, "TRANSPORT_UDP", 1200);
    PyModule_AddIntConstant(g, "TRANSPORT_TCP", 1201);
    PyModule_AddIntConstant(g, "TRANSPORT_TLS", 1202);
    PyModule_AddIntConstant(g, "TRANSPORT_STARTTLS", 1203);

/*
 * suffix appending methods
 */

    PyModule_AddIntConstant(g, "APPEND_NAME_ALWAYS", 550);
    PyModule_AddIntConstant(g, "APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE", 551);
    PyModule_AddIntConstant(g, "APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE", 552);
    PyModule_AddIntConstant(g, "APPEND_NAME_NEVER", 553);

/*
 * context codes
 */
    PyModule_AddIntConstant(g, "CONTEXT_CODE_NAMESPACES", 600);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_RESOLUTION_TYPE", 601);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_FOLLOW_REDIRECTS", 602);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_UPSTREAM_RECURSIVE_SERVERS", 603);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_DNS_ROOT_SERVERS", 604);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_DNS_TRANSPORT", 605);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_LIMIT_OUTSTANDING_QUERIES", 606);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_APPEND_NAME", 607);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_SUFFIX", 608);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_DNSSEC_TRUST_ANCHORS", 609);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_EDNS_MAXIMUM_UDP_PAYLOAD_SIZE", 610);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_EDNS_EXTENDED_RCODE", 611);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_EDNS_VERSION", 612);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_EDNS_DO_BIT", 613);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_DNSSEC_ALLOWED_SKEW", 614);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_MEMORY_FUNCTIONS", 615);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_TIMEOUT", 616);
    PyModule_AddIntConstant(g, "CONTEXT_CODE_IDLE_TIMEOUT", 617);
    
/*
 *  callback types
 */

    PyModule_AddIntConstant(g, "CALLBACK_COMPLETE", 700);
    PyModule_AddIntConstant(g, "CALLBACK_CANCEL", 701);
    PyModule_AddIntConstant(g, "CALLBACK_TIMEOUT", 702);
    PyModule_AddIntConstant(g, "CALLBACK_ERROR", 703);

/*
 * name service types
 */

    PyModule_AddIntConstant(g, "GETDNS_NAMETYPE_DNS", 800);
    PyModule_AddIntConstant(g, "GETDNS_NAMETYPE_WINS", 801);

    PyModule_AddIntConstant(g, "CALLBACK_COMPLETE", 700);
    PyModule_AddIntConstant(g, "CALLBACK_CANCEL", 701);
    PyModule_AddIntConstant(g, "CALLBACK_TIMEOUT", 702);
    PyModule_AddIntConstant(g, "CALLBACK_ERROR", 703);

    PyModule_AddIntConstant(g, "RESPSTATUS_GOOD", 900);
    PyModule_AddIntConstant(g, "RESPSTATUS_NO_NAME", 901);
    PyModule_AddIntConstant(g, "RESPSTATUS_ALL_TIMEOUT", 902);
    PyModule_AddIntConstant(g, "RESPSTATUS_NO_SECURE_ANSWERS", 903);
    PyModule_AddIntConstant(g, "RESPSTATUS_ALL_BOGUS_ANSWERS", 904);

    PyModule_AddIntConstant(g, "EXTENSION_TRUE", 1000);
    PyModule_AddIntConstant(g, "EXTENSION_FALSE", 1001);

    PyModule_AddIntConstant(g, "BAD_DNS_CNAME_IN_TARGET", 1100);
    PyModule_AddIntConstant(g, "BAD_DNS_ALL_NUMERIC_LABEL", 1101);
    PyModule_AddIntConstant(g, "BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE", 1102);

/*
 * rr type constants
 */

    PyModule_AddIntConstant(g, "RRTYPE_A", 1);
    PyModule_AddIntConstant(g, "RRTYPE_NS", 2);
    PyModule_AddIntConstant(g, "RRTYPE_MD", 3);
    PyModule_AddIntConstant(g, "RRTYPE_MF", 4);
    PyModule_AddIntConstant(g, "RRTYPE_CNAME", 5);
    PyModule_AddIntConstant(g, "RRTYPE_SOA", 6);
    PyModule_AddIntConstant(g, "RRTYPE_MB", 7);
    PyModule_AddIntConstant(g, "RRTYPE_MG", 8);
    PyModule_AddIntConstant(g, "RRTYPE_MR", 9);
    PyModule_AddIntConstant(g, "RRTYPE_NULL", 10);
    PyModule_AddIntConstant(g, "RRTYPE_WKS", 11);
    PyModule_AddIntConstant(g, "RRTYPE_PTR", 12);
    PyModule_AddIntConstant(g, "RRTYPE_HINFO", 13);
    PyModule_AddIntConstant(g, "RRTYPE_MINFO", 14);
    PyModule_AddIntConstant(g, "RRTYPE_MX", 15);
    PyModule_AddIntConstant(g, "RRTYPE_TXT", 16);
    PyModule_AddIntConstant(g, "RRTYPE_RP", 17);
    PyModule_AddIntConstant(g, "RRTYPE_AFSDB", 18);
    PyModule_AddIntConstant(g, "RRTYPE_X25", 19);
    PyModule_AddIntConstant(g, "RRTYPE_ISDN", 20);
    PyModule_AddIntConstant(g, "RRTYPE_RT", 21);
    PyModule_AddIntConstant(g, "RRTYPE_NSAP", 22);
    PyModule_AddIntConstant(g, "RRTYPE_SIG", 24);
    PyModule_AddIntConstant(g, "RRTYPE_KEY", 25);
    PyModule_AddIntConstant(g, "RRTYPE_PX", 26);
    PyModule_AddIntConstant(g, "RRTYPE_GPOS", 27);
    PyModule_AddIntConstant(g, "RRTYPE_AAAA", 28);
    PyModule_AddIntConstant(g, "RRTYPE_LOC", 29);
    PyModule_AddIntConstant(g, "RRTYPE_NXT", 30);
    PyModule_AddIntConstant(g, "RRTYPE_EID", 31);
    PyModule_AddIntConstant(g, "RRTYPE_NIMLOC", 32);
    PyModule_AddIntConstant(g, "RRTYPE_SRV", 33);
    PyModule_AddIntConstant(g, "RRTYPE_ATMA", 34);
    PyModule_AddIntConstant(g, "RRTYPE_NAPTR", 35);
    PyModule_AddIntConstant(g, "RRTYPE_KX", 36);
    PyModule_AddIntConstant(g, "RRTYPE_CERT", 37);
    PyModule_AddIntConstant(g, "RRTYPE_A6", 38);
    PyModule_AddIntConstant(g, "RRTYPE_DNAME", 39);
    PyModule_AddIntConstant(g, "RRTYPE_SINK", 40);
    PyModule_AddIntConstant(g, "RRTYPE_OPT", 41);
    PyModule_AddIntConstant(g, "RRTYPE_APL", 42);
    PyModule_AddIntConstant(g, "RRTYPE_DS", 43);
    PyModule_AddIntConstant(g, "RRTYPE_SSHFP", 44);
    PyModule_AddIntConstant(g, "RRTYPE_IPSECKEY", 45);
    PyModule_AddIntConstant(g, "RRTYPE_RRSIG", 46);
    PyModule_AddIntConstant(g, "RRTYPE_NSEC", 47);
    PyModule_AddIntConstant(g, "RRTYPE_DNSKEY", 48);
    PyModule_AddIntConstant(g, "RRTYPE_DHCID", 49);
    PyModule_AddIntConstant(g, "RRTYPE_NSEC3", 50);
    PyModule_AddIntConstant(g, "RRTYPE_NSEC3PARAM", 51);
    PyModule_AddIntConstant(g, "RRTYPE_TLSA", 52);
    PyModule_AddIntConstant(g, "RRTYPE_HIP", 55);
    PyModule_AddIntConstant(g, "RRTYPE_NINFO", 56);
    PyModule_AddIntConstant(g, "RRTYPE_RKEY", 57);
    PyModule_AddIntConstant(g, "RRTYPE_TALINK", 58);
    PyModule_AddIntConstant(g, "RRTYPE_CDS", 59);
    PyModule_AddIntConstant(g, "RRTYPE_CDNSKEY", 60);
    PyModule_AddIntConstant(g, "RRTYPE_OPENPGPKEY", 61);
    PyModule_AddIntConstant(g, "RRTYPE_CSYNC", 62);
    PyModule_AddIntConstant(g, "RRTYPE_SPF", 99);
    PyModule_AddIntConstant(g, "RRTYPE_UINFO", 100);
    PyModule_AddIntConstant(g, "RRTYPE_UID", 101);
    PyModule_AddIntConstant(g, "RRTYPE_GID", 102);
    PyModule_AddIntConstant(g, "RRTYPE_UNSPEC", 103);
    PyModule_AddIntConstant(g, "RRTYPE_NID", 104);
    PyModule_AddIntConstant(g, "RRTYPE_L32", 105);
    PyModule_AddIntConstant(g, "RRTYPE_L64", 106);
    PyModule_AddIntConstant(g, "RRTYPE_LP", 107);
    PyModule_AddIntConstant(g, "RRTYPE_EUI48", 108);
    PyModule_AddIntConstant(g, "RRTYPE_EUI64", 109);
    PyModule_AddIntConstant(g, "RRTYPE_TKEY", 249);
    PyModule_AddIntConstant(g, "RRTYPE_TSIG", 250);
    PyModule_AddIntConstant(g, "RRTYPE_IXFR", 251);
    PyModule_AddIntConstant(g, "RRTYPE_AXFR", 252);
    PyModule_AddIntConstant(g, "RRTYPE_MAILB", 253);
    PyModule_AddIntConstant(g, "RRTYPE_MAILA", 254);
    PyModule_AddIntConstant(g, "RRTYPE_ANY", 255);
    PyModule_AddIntConstant(g, "RRTYPE_URI", 256);
    PyModule_AddIntConstant(g, "RRTYPE_CAA", 257);
    PyModule_AddIntConstant(g, "RRTYPE_TA", 32768);
    PyModule_AddIntConstant(g, "RRTYPE_DLV", 32769);

    PyModule_AddIntConstant(g, "RRCLASS_IN", 1);
    PyModule_AddIntConstant(g, "RRCLASS_CH", 3);
    PyModule_AddIntConstant(g, "RRCLASS_HS", 4);
    PyModule_AddIntConstant(g, "RRCLASS_NONE", 254);
    PyModule_AddIntConstant(g, "RRCLASS_ANY", 255);

    PyModule_AddIntConstant(g, "OPCODE_QUERY", 0);
    PyModule_AddIntConstant(g, "OPCODE_IQUERY", 1);
    PyModule_AddIntConstant(g, "OPCODE_STATUS", 2);
    PyModule_AddIntConstant(g, "OPCODE_NOTIFY", 4);
    PyModule_AddIntConstant(g, "OPCODE_UPDATE", 5);

    PyModule_AddIntConstant(g, "RCODE_NOERROR", 0);
    PyModule_AddIntConstant(g, "RCODE_FORMERR", 1);
    PyModule_AddIntConstant(g, "RCODE_SERVFAIL", 2);
    PyModule_AddIntConstant(g, "RCODE_NXDOMAIN", 3);
    PyModule_AddIntConstant(g, "RCODE_NOTIMP", 4);
    PyModule_AddIntConstant(g, "RCODE_REFUSED", 5);
    PyModule_AddIntConstant(g, "RCODE_YXDOMAIN", 6);
    PyModule_AddIntConstant(g, "RCODE_YXRRSET", 7);
    PyModule_AddIntConstant(g, "RCODE_NXRRSET", 8);
    PyModule_AddIntConstant(g, "RCODE_NOTAUTH", 9);
    PyModule_AddIntConstant(g, "RCODE_NOTZONE", 10);
    PyModule_AddIntConstant(g, "RCODE_BADVERS", 16);
    PyModule_AddIntConstant(g, "RCODE_BADSIG", 16);
    PyModule_AddIntConstant(g, "RCODE_BADKEY", 17);
    PyModule_AddIntConstant(g, "RCODE_BADTIME", 18);
    PyModule_AddIntConstant(g, "RCODE_BADMODE", 19);
    PyModule_AddIntConstant(g, "RCODE_BADNAME", 20);
    PyModule_AddIntConstant(g, "RCODE_BADALG", 21);
    PyModule_AddIntConstant(g, "RCODE_BADTRUNC", 22);

/*
 * extras
 */

/*
 * values for tls_authentication
 */

    PyModule_AddIntConstant(g, "AUTHENTICATION_NONE", 1300);
    PyModule_AddIntConstant(g, "AUTHENTICATION_HOSTNAME", 1301);
}
