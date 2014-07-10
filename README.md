getdns-python-bindings
======================

Python bindings for getdns

External dependencies
=====================

Built and tested against Python 2.7.  You will need to install
the Python headers and libraries - this is usually a package
called "python-dev"

Currently building against the getdns 0.1.3 release.
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

Documentation
=============

Documentation is formatted using the [sphinx](http://sphinx-doc.org/)
documentation system.  The html-formatted output is under the pygetdns
source tree in doc/_build/html.  It is also available online at [readthedogs.org]
(https://getdns.readthedocs.org/)

Changes from the earlier release
================================

We've introduced a Context object with attributes and methods, with
queries being Context methods.  Attributes can be assigned and read
directly without using the getdns setters and getters.  For example,

```python
import getdns.context
my_context = getdns.Context()
my_context.timeout = 1000
print my_context.timeout
```

Please see the documentation for details on attributes and methods.

Examples
========

There are several sample scripts in the examples directory, showing how to 
issue different kinds of queries, how to verify the answer status and DNSSEC
status, and so on.

