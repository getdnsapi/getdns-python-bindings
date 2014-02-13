#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include "pygetdns.h"


struct getdns_dict *
extensions_to_getdnsdict(PyDictObject *pydict)
{
    struct getdns_dict *newdict = 0;
    Py_ssize_t pos = 0;
    PyObject *key, *value;
    int  tmp_int;
    char *tmp_key;

    if (!PyDict_Check(pydict))  {
        PyErr_SetString(getdns_error, "Expected dict, didn't get one");
        return NULL;
    }
    newdict = getdns_dict_create();
    while (PyDict_Next((PyObject *)pydict, &pos, &key, &value))  {
        tmp_key = PyString_AsString(PyObject_Str(key));
        if ( (!strncmp(tmp_key, "dnssec_return_status", strlen("dnssec_return_status")))  ||
             (!strncmp(tmp_key, "return_both_v4_and_v6", strlen("return_both_v4_and_v6"))) )  {
            if (!PyInt_Check(value))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                return NULL;
            }
            tmp_int = (int)PyInt_AsLong(value);
            (void)getdns_dict_set_int(newdict, tmp_key, tmp_int);
        } else {
            PyErr_SetString(getdns_error, GETDNS_RETURN_NO_SUCH_EXTENSION_TEXT);
            return NULL;
        }
    }
    return newdict;
}


PyObject *
decode_getdns_response(struct getdns_dict *response)
{
    uint32_t error;
    char error_str[512];
    struct getdns_list *addr_list;
    size_t n_addrs;
    getdns_return_t ret;
    size_t i;
    struct getdns_dict *addr_dict;
    struct getdns_bindata *addr;
    char *addr_str;
    PyObject *results;

    (void)getdns_dict_get_int(response, "status", &error);
    if (error != GETDNS_RESPSTATUS_GOOD)  {
        sprintf(error_str, "No answers, return value %d", error);
        PyErr_SetString(getdns_error, error_str);
        return NULL;
    }
    if ((ret = getdns_dict_get_list(response, "just_address_answers",
                                    &addr_list)) != GETDNS_RETURN_GOOD)  {
        sprintf(error_str, "Extracting answers failed: %d", ret);
        PyErr_SetString(getdns_error, error_str);
        return NULL;
    }
    if ((results = PyList_New(0)) == NULL)  {
        PyErr_SetString(getdns_error, "Unable to allocate response list");
        return NULL;
    }
    (void)getdns_list_get_length(addr_list, &n_addrs);
    for ( i = 0 ; i < n_addrs ; i++ )  {
        (void)getdns_list_get_dict(addr_list, i, &addr_dict);
        (void)getdns_dict_get_bindata(addr_dict, "address_data", &addr);
        addr_str = getdns_display_ip_address(addr);
        PyList_Append(results, PyString_FromString(addr_str));
    }
    return results;
}
