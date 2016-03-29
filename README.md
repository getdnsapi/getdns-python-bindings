getdns-python-bindings
======================

Python bindings for getdns

* Date: 2016-03-29
* Github: https://github.com/getdnsapi/getdns-python-bindings
* Current version: v1.0beta

External dependencies
=====================

Built and tested against Python 2.7 and Python 3.4.  You will need to install
the Python headers and libraries - this is usually a package
called "python-dev"

Currently building against the getdns v0.9.0 release.
getdns external dependencies include:

* [libunbound from NLnet Labs](http://www.nlnetlabs.nl/projects/unbound/) version 1.4.16 or later
* [libidn from the FSF](http://www.gnu.org/software/libidn/) version 1.
* [libssl and libcrypto from the OpenSSL project](https://www.openssl.org/) version 0.9.7 or later.
  (Note: version 1.0.1 or later is required for TLS support, 
   version 1.0.2 or later is required for TLS hostname authentication)

Building
========
To build, 

```
python setup.py build 
````

During the development process and before the module is installed, I
find it convenient to have a symlink in the current directory pointing
to the library in the build directory.  For example:

```
getdns.so -> build/lib.linux-i686-2.7/getdns.so
```

This is only useful if you're working on the actual bindings code;
people who are using the bindings should go ahead and install.

 To install,

```
python setup.py install
````

We recently added Python 3 support.  To build, just invoke
the Python 3 interpreter rather the Python 2 interpreter (on
most systems this will be "python3").  

```
python3 setup.py build
```
You will need the
Python 3 development environment ("python3-dev" or
"python3-devel", most often).


Documentation
=============

Documentation is formatted using the [sphinx](http://sphinx-doc.org/)
documentation system.  The html-formatted output is under the pygetdns
source tree in doc/_build/html.  It is also available online at [readthedocs.org]
(https://getdns.readthedocs.org/)

Changes from the earlier release
================================

* A number of performance improvements.

* Installable via PyPi.

* Removed libevent dependency

* For consistency with Python 3, the Python 2 bindings now return
Context() attributes as longs

* TSIG support

* GETDNS_AUTHENTICATION_HOSTNAME is replaced by
GETDNS_AUTHENTICATION_REQUIRED (but remains available as an alias).
Upstreams can now be configured with either a hostname or a SPKI
pinset for TLS authentication (or both). If the
GETDNS_AUTHENTICATION_REQUIRED option is used at least one piece of
authentication information must be configured for each upstream, and
all the configured authentication information for an upstream must
validate.

Older changes
=============

In addition to adding Python 3 support, we've changed the callback
argument to the asynchronous methods to accept a callable by name,
rather than as a literal string.

We're also now supporting a new transport_list attribute, an
ordered (by preference) list of transport options, including
TCP, UDP, TLS, and STARTTLS.

There are also a number of bugfixes, including cleaning up
after unbound zombies (this has been fixed in unbound as well
but the code is not yet included in a distribution) and
correct handling of strings encoded as getdns bindatas.

Examples have been updated to work with both Python 2.x and
Python 3.

Please see the documentation for details on new attributes 
extensions, and methods.

Examples
========

There are several sample scripts in the examples directory, showing how to 
issue different kinds of queries, how to verify the answer status and DNSSEC
status, and so on.

