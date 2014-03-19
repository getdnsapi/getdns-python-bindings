getdns-python-bindings
======================

Python bindings for getdns

External dependencies
=====================

Built and tested against Python 2.7.  You will need to install
the Python headers and libraries - this is usually a package
called "python-dev"

Currently building against the getdns "develop" branch (to be released
as 0.1.1).  getdns external dependencies include:

* [libldns from NLnet Labs](https://www.nlnetlabs.nl/projects/ldns/) version 1.6.11 or later (ldns requires ope
nssl headers and libraries)
* [libunbound from NLnet Labs](http://www.nlnetlabs.nl/projects/unbound/) version 1.4.16 or later
* [libexpat](http://expat.sourceforge.net/) for libunbound.
* [libidn from the FSF](http://www.gnu.org/software/libidn/) version 1.
* [libevent](http://libevent.org) version 2.0.21 stable, sometimes called libevent2 (only needed if you plan to
 use it for asynchronous handling)

Building
========
To build, 

```
python setup.py build 
````

I find it convenient to have a symlink in the current directory
pointing to the library in the build directory:

```
getdns.so -> build/lib.linux-i686-2.7/getdns.so
```

To install, 

```
python setup.py install
````

Examples
========

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
