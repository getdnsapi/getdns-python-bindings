/*
 * Copyright (c) 2015, Versign, Inc.
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


/*
 *  Get the address of the Python function object
 *    being passed in by name to the context
 *    query methods
 */

PyObject *
get_callback(char *py_main, char *callback)
{
    PyObject *main_module;
    PyObject *main_dict;
    PyObject *callback_func;

    if ((main_module = PyImport_AddModule(py_main)) == 0)  {
        PyErr_SetString(getdns_error, "No 'main'");
        return NULL;
    }
    main_dict = PyModule_GetDict(main_module);
    if ((callback_func = PyDict_GetItemString(main_dict, callback)) == 0)  {
        PyErr_SetString(getdns_error, "callback not found\n");
        return NULL;
    }
    if (!PyCallable_Check(callback_func))  {
        PyErr_SetString(getdns_error, "The callback function is not runnable");
        return NULL;
    }
    return callback_func;
}

    
void
callback_shim(struct getdns_context *context,
              getdns_callback_type_t type,
              struct getdns_dict *response,
              void *userarg,
              getdns_transaction_t tid)
{
    PyObject *py_callback_type;
    PyObject *py_result;
    PyObject *py_tid;
    PyObject *py_userarg;

    userarg_blob *u = (userarg_blob *)userarg;
#if PY_MAJOR_VERSION >= 3
    if ((py_callback_type = PyLong_FromLong((long)type)) == NULL)  {
#else
    if ((py_callback_type = PyInt_FromLong((long)type)) == NULL)  {
#endif
        PyObject *err_type, *err_value, *err_traceback;
        PyErr_Fetch(&err_type, &err_value, &err_traceback);
        PyErr_Restore(err_type, err_value, err_traceback);
        return;
    }
    if (type == GETDNS_CALLBACK_CANCEL)  {
        py_result = Py_None;
        py_tid = Py_None;
        py_userarg = Py_None;
    }  else  {
        py_result = result_create(response);
#if PY_MAJOR_VERSION >= 3
        py_tid = PyLong_FromLong((long)tid);
#else
        py_tid = PyInt_FromLong((long)tid);
#endif
        if (u->userarg)
#if PY_MAJOR_VERSION >= 3
            py_userarg = PyUnicode_FromString(u->userarg);
#else
            py_userarg = PyString_FromString(u->userarg);
#endif
        else
            py_userarg = Py_None;
    }
    PyObject_CallFunctionObjArgs(u->callback_func, py_callback_type, py_result, py_userarg, py_tid, NULL);
}
