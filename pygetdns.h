/**
 * defines, declarations, and globals for pygetdns
 */


static PyObject *getdns_error;
void *context_destructor(PyObject *capsule);
struct getdns_dict *pydict_to_getdnsdict(PyDictObject *);
