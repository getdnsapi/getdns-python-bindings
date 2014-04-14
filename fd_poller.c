/**
 *
 * \file fd_poller.c
 * @brief pygetdns support for file descriptor polling
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
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include <getdns/getdns_ext_libevent.h>
#include <event2/event.h>
#include "pygetdns.h"


PyObject *
context_fd(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        0
    };

    PyObject *context_capsule;
    struct getdns_context *context;
    int  fd;
    FILE *t;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "O", kwlist,
                                     &context_capsule))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((fd = getdns_context_fd(context)) < 0)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    if ((t = fdopen(fd, "r")) == NULL)  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_GENERIC_ERROR_TEXT);
        return NULL;
    }
    return (PyFile_FromFile(t, "<context>", "r", NULL));
}


PyObject *
context_get_num_pending_requests(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        "timeout",
        0
    };

    PyObject *context_capsule;
    struct getdns_context *context;
    uint64_t timeout = 0;
    struct timeval tv;
    uint32_t n_requests;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "O|L", kwlist,
                                     &context_capsule, &timeout))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if (timeout)  {
        tv.tv_sec = timeout / 1000; /* timeout is expressed in milliseconds */
        tv.tv_usec = (timeout % 1000) * 1000;
    }
    return (PyInt_FromLong((long)getdns_context_get_num_pending_requests(context, &tv)));
}
    

PyObject *
context_process_async(PyObject *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {
        "context",
        0
    };

    PyObject *context_capsule;
    struct getdns_context *context;
    getdns_return_t ret;
    char err_buf[256];

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "O", kwlist,
                                     &context_capsule))  {
        PyErr_SetString(getdns_error, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        return NULL;
    }
    context = PyCapsule_GetPointer(context_capsule, "context");
    if ((ret = getdns_context_process_async(context)) != GETDNS_RETURN_GOOD)  {
        getdns_strerror(ret, err_buf, sizeof err_buf);
        PyErr_SetString(getdns_error, err_buf);
        return NULL;
    }
    return Py_None;
}
