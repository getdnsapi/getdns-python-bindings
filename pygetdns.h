/**
 * defines, declarations, and globals for pygetdns
 */


static PyObject *getdns_error;
struct getdns_dict *extensions_to_getdnsdict(PyDictObject *);
PyObject *decode_getdns_response(struct getdns_dict *);
