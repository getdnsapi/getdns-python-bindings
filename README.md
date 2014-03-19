getdns-python-bindings
======================

Python bindings for getdns

Built and tested against Python 2.7.  You will need to install
the Python headers and libraries - this is usually a package
called "python-dev"

To build, 

```
python setup.py build 
````

I find it convenient to have a symlink in the current directory
pointing to the library in the build directory:

```
getdns.so -> build/lib.linux-i686-2.7/getdns.so
```

Brief sample code, synchronous:
```
import getdns
c = getdns.context_create()
ext = { "return_both_v4_and_v6"  :  getdns.GETDNS_EXTENSION_TRUE, "add_warning_for_bad_dns" : getdns.GETDNS_EXTENSION_TRUE  }
getdns.general(c, "www.google.com", getdns.GETDNS_RRTYPE_A, ext)
```

Brief sample code, asynchronous: 
```
import getdns

def process_response(c, resp,  str):
    print 'In callback ... '
    print resp

c = getdns.context_create()
ext = { "return_both_v4_and_v6"  :  getdns.GETDNS_EXTENSION_TRUE, "add_warning_for_bad_dns" : getdns.GETDNS_EXTENSION_TRUE  }
getdns.general(c, "www.google.com", getdns.GETDNS_RRTYPE_A, ext, callback='process_response')
```
