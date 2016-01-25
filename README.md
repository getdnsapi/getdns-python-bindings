getdns-python-bindings
======================

Python bindings for getdns

External dependencies
=====================

Built and tested against Python 2.7 and Python 3.4.  You will need to install
the Python headers and libraries - this is usually a package
called "python-dev"

Currently building against the getdns v0.9.0 release.
getdns external dependencies include:

* [libldns from NLnet Labs](https://www.nlnetlabs.nl/projects/ldns/) version 1.6.11 or later (ldns requires ope
nssl headers and libraries)
* [libunbound from NLnet Labs](http://www.nlnetlabs.nl/projects/unbound/) version 1.4.16 or later
* [libexpat](http://expat.sourceforge.net/) for libunbound.
* [libidn from the FSF](http://www.gnu.org/software/libidn/) version 1.
* [libevent](http://libevent.org) version 2.0.21 stable, sometimes called libevent2 (only needed if you plan to
 use it for asynchronous handling)

Note that getdns **MUST** be built with the --with-libevent flag to
configure.

Building
========
To build, 

```
python setup.py build 
````

During the development process and before the module is installed, I
find it convenient to have a symlink in the current directory pointing
to the library in the build directory:

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

