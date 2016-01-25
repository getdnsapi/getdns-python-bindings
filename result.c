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
#include <structmember.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>
#include <event2/event.h>
#include <pthread.h>
#include "pygetdns.h"


#if !defined(Py_TYPE)
    #define Py_TYPE(ob)  (((PyObject *)(ob))->ob_type)
#endif

int
result_init(getdns_ResultObject *self, PyObject *args, PyObject *keywds)
{
    PyObject *result_capsule;
    struct getdns_dict *result_dict;
    int  status;
    int  answer_type;
    char *canonical_name;

    if (!PyArg_ParseTuple(args, "|O", &result_capsule))  {
        PyErr_SetString(PyExc_AttributeError, GETDNS_RETURN_INVALID_PARAMETER_TEXT);
        Py_DECREF(self);
        return -1;
    }
    if ((result_dict = PyCapsule_GetPointer(result_capsule, "result")) == NULL)  {
        PyErr_SetString(PyExc_AttributeError, "Unable to initialize result object");
        Py_DECREF(self);
        return -1;
    }
    if ((self->replies_full = gdict_to_pdict(result_dict)) == NULL)  {
        Py_DECREF(self);
        return -1;
    }
    if ((self->replies_tree = get_replies_tree(result_dict)) == NULL)  {
        Py_DECREF(self);
        return -1;
    }
    if ((status = get_status(result_dict)) == 0)  {
        Py_DECREF(self);
        return -1;
    }
#if PY_MAJOR_VERSION >= 3
    self->status = PyLong_FromLong((long)status);
#else
    self->status = PyInt_FromLong((long)status);
#endif
    if ((answer_type = get_answer_type(result_dict)) == 0)  {
        Py_DECREF(self);
        return -1;
    }
#if PY_MAJOR_VERSION >= 3
    self->answer_type = PyLong_FromLong((long)answer_type);
#else
    self->answer_type = PyInt_FromLong((long)answer_type);
#endif
    if ((canonical_name = get_canonical_name(result_dict)) == 0)  
        self->canonical_name = Py_None;
    else
#if PY_MAJOR_VERSION >= 3
        self->canonical_name = PyUnicode_FromString(canonical_name);
#else
        self->canonical_name = PyString_FromString(canonical_name);
#endif
    if ((self->just_address_answers = get_just_address_answers(result_dict)) == NULL)  {
        self->just_address_answers = Py_None;
    }
    if ((self->validation_chain = get_validation_chain(result_dict)) == NULL)  
        self->validation_chain = Py_None;
#if GETDNS_NUMERIC_VERSION < 0x00090000
    if ((self->call_debugging = get_call_debugging(result_dict)) == NULL)
        self->call_debugging = Py_None;
#else
    if ((self->call_reporting = get_call_reporting(result_dict)) == NULL)
        self->call_reporting = Py_None;
#endif
    return 0;
}


PyObject *
result_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    getdns_ResultObject *self;

    self = (getdns_ResultObject *)type->tp_alloc(type, 0);
    if (self != NULL)  {
        self->just_address_answers = Py_None;
        self->answer_type = Py_None;
        self->status = Py_None;
        self->replies_tree = Py_None;
        self->canonical_name = Py_None;
        self->replies_full = Py_None;
        self->validation_chain = Py_None;
#if GETDNS_NUMERIC_VERSION < 0x00090000
        self->call_debugging = Py_None;
#else
        self->call_reporting = Py_None;
#endif
    }
    return (PyObject *)self;
}



void
result_dealloc(getdns_ResultObject *self)
{
    Py_XDECREF(self->just_address_answers);
    Py_XDECREF(self->answer_type);
    Py_XDECREF(self->status);
    Py_XDECREF(self->replies_tree);
    Py_XDECREF(self->replies_full);
    Py_XDECREF(self->canonical_name);
    Py_XDECREF(self->validation_chain);
#if GETDNS_NUMERIC_VERSION < 0x00090000
    Py_XDECREF(self->call_debugging);
#else
    Py_XDECREF(self->call_reporting);
#endif

#if PY_MAJOR_VERSION >= 3
    Py_TYPE(self)->tp_free((PyObject *)self);
#else
    self->ob_type->tp_free((PyObject *)self);
#endif
}


PyObject *
result_getattro(PyObject *self, PyObject *nameobj)
{
    Py_RETURN_NONE;
}


PyObject *
result_str(PyObject *self)
{
    getdns_ResultObject *me = (getdns_ResultObject *)self;
    PyObject *cname;

    cname = me->canonical_name;
    Py_INCREF(cname);
    return cname;
}
    


/*
 * package up a getdns response dict and use it to
 * build a new Python result object
 */

PyObject *
result_create(struct getdns_dict *resp)
{
    PyObject *result_capsule;
    PyObject *args;

    result_capsule = PyCapsule_New(resp, "result", 0);
    args = Py_BuildValue("(O)", result_capsule);
    return PyObject_CallObject((PyObject *)&getdns_ResultType, args);
}
