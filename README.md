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

Known issues
============

There are several issues in this alpha release which we expect to be resolved
prior to the TNW hack battle.  These include:

* full module documentation
* the asynchronous code is not actually asynchronous; it invokes the
  callback but the calling function blocks until the callback returns
* getdns exception error strings are not "bubbling up" to the user
  from deeply nested functions.  You may see an exception thrown with
  a warning that the error string is not set as a result

Examples
========

There are several sample scripts in the examples directory, showing how to 
issue different kinds of queries, how to verify the answer status and DNSSEC
status, and so on.

