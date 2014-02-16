#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include "pygetdns.h"



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
                                     &set_from_os))
        return 0;
    if ((ret = getdns_context_create(&context, set_from_os)) != GETDNS_RETURN_GOOD)  {
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }

    py_context = PyCapsule_New(context, "context", NULL);
    Py_INCREF(py_context);
    return py_context;
    
}


static PyObject *
general(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "name",
        "request_type",
        "extensions",
        "callback",
        0
    };

    PyObject *context_capsule;
    struct getdns_context *context;
    char *name;
    uint16_t  request_type;
    PyDictObject *extensions_obj;
    struct getdns_dict *extensions_dict;
    int callback = 0;
    getdns_return_t ret;
    struct getdns_dict *resp = 0;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OsH|OO" , kwlist,
                                     &context_capsule, &name, &request_type,
                                     &extensions_obj, &callback))  {
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((extensions_dict = extensions_to_getdnsdict(extensions_obj)) == 0)  {
        PyErr_SetString(getdns_error, "Dictionary parse failure");
        return NULL;
    }
    if ((ret = getdns_general_sync(context, name, GETDNS_RRTYPE_A,
                                   extensions_dict, &resp)) != GETDNS_RETURN_GOOD)  {
        PyErr_SetString(getdns_error, "Lookup failure");
        return NULL;
    }
#if 0
    (void)getdns_list_get_length(resp, &list_len);
    printf("%d answers\n", list_len);

    for ( i = 0 ; i < list_len ; i++ )  {
        getdns_list_get_bindata(resp, i, &resp_item);
        printf("%s\n", resp_item->data);
    }
#endif
    return decode_getdns_response(resp);

}

/*
 * Implements the results_tree for the getDns API
 * Returns a PyObject with the response.
 */
static PyObject *
replies_tree(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "name",
        "request_type",
        "extensions",
        "callback",
        0
    };

    PyObject *context_capsule;
    struct getdns_context *context;
    char *name;
    uint16_t  request_type;
    PyDictObject *extensions_obj;
    struct getdns_dict *extensions_dict;
    int callback = 0;
    getdns_return_t ret;
    struct getdns_dict *resp = 0;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "OsH|OO" , kwlist,
                                     &context_capsule, &name, &request_type,
                                     &extensions_obj, &callback))  {
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((extensions_dict = extensions_to_getdnsdict(extensions_obj)) == 0)  {
        PyErr_SetString(getdns_error, "Dictionary parse failure");
        return NULL;
    }
    if ((ret = getdns_general_sync(context, name, request_type,
                                   extensions_dict, &resp))
    		                       != GETDNS_RETURN_GOOD)  {
    	//TODO: refine error handling consistently thru the app, a error handler
    	// with helpful messages.
    	char error[255];
    	sprintf(error, "getdns_general_sync failed with error code = %d", ret);
        PyErr_SetString(getdns_error, error);
        return NULL;
    }
#if 0 
    int list_len;
    (void)getdns_list_get_length(resp, &list_len);
    printf("%d answers\n", list_len);
    int i = 0;
    struct getdns_bindata *resp_item;
    for ( i = 0 ; i < list_len ; i++ )  {
        getdns_list_get_bindata(resp, i, &resp_item);
        printf("Item %s\n", resp_item->data);
    }
#endif
    return decode_getdns_results_tree_response(resp);

}


static struct PyMethodDef getdns_methods[] = {
    { "context_create", (PyCFunction)context_create, METH_KEYWORDS },
    { "general", (PyCFunction)general, METH_KEYWORDS },
    { "replies_tree", (PyCFunction)replies_tree, METH_KEYWORDS },
    { 0, 0 }
};

PyMODINIT_FUNC
initgetdns(void)
{
    PyObject *g;
#if 0
    static PyObject *getdns_error;
#endif
    if ((g = Py_InitModule("getdns", getdns_methods)) == NULL)
        return;
    getdns_error = PyErr_NewException("getdns.error", NULL, NULL);
    Py_INCREF(getdns_error);
    PyModule_AddObject(g, "error", getdns_error);
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
    PyModule_AddIntConstant(g, "GETDNS_EXTENSION_TRUE", 1000);
    PyModule_AddIntConstant(g, "GETDNS_EXTENSION_FALSE", 1001);
}

