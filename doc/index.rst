.. getdns documentation master file, created by
   sphinx-quickstart on Mon Apr  7 17:05:52 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

getdns: Python bindings for getdns
####################################

"getdns" is an implementation of Python language bindings
for the `getdns <http://getdnsapi.net/>`_ API.  getdns is a
modern, asynchronous DNS API that simplifies access to
advanced DNS features, including DNSSEC.  The API
`specification <http://www.vpnc.org/getdns-api/>`_ was
developed by Paul Hoffman.  getdns is built on top of the
getdns implementation developed as a joint project between
`Verisign Labs
<http://labs.verisigninc.com/en_US/innovation/verisign-labs/index.xhtml>`_
and `NLnet Labs <http://nlnetlabs.nl/>`_.

We have tried to keep this interface as Pythonic as we can
while staying true to the getdns architecture.  With this 
release we are moving towards a design that is more consistent with
Python object design.

Dependencies
============

This version of getdns has been built and tested against Python
2.7.  We also expect these other prerequisites to be
installed:

* `libgetdns <http://getdnsapi.net/>`_, version 0.1.2 or later
* `libldns <https://www.nlnetlabs.nl/projects/ldns/>`_,
  version 1.6.11 or later
* `libunbound
  <http://www.nlnetlabs.nl/projects/unbound/>`_, version
  1.4.16 or later
* `libexpat <http://expat.sourceforge.net/>`_ (needed for unbound)
* `libidn <http://www.gnu.org/software/libidn/>`_ version 1
* `libevent <http://libevent.org/>`_ version 2.0.21 stable

n.b.: libgetdns *must* be built with the libevent extension,
as follows:
::

  ./configure --with-libevent

Building
========

The code repository for getdns is available at:
`<https://github.com/getdnsapi/getdns-python-bindings>`_.  If you are building from source you will
need the Python development package for Python 2.7.  On
Linux systems this is typically something along the lines of
"python-dev" or "python2.7-dev", available through your
package system.  On Mac OS we are building against the
python.org release, available in source form `here
<https://www.python.org/download/releases/2.7.4>`_.

For the actual build, we are using the standard Python
`distutils <https://docs.python.org/2/distutils/>`_.  To
build and install:
::

  python setup.py build
  python setup.py install


Using getdns
==============

Contexts
--------

All getdns queries happen within a resolution *context*, and among
the first tasks you'll need to do before issuing a query is
to acquire a Context object.  A context is
an opaque object with attributes describing the environment within
which the query and replies will take place, including
elements such as DNSSEC validation, whether the resolution
should be performed as a recursive resolver or a stub
resolver, and so on.  Individual Context attributes may be
examined directly, and the overall state of a given context can be
queried with the Context.get_api_information() method.

See section 8 of the `API
specification <http://www.vpnc.org/getdns-api/>`_


Examples
--------

In this example, we do a simple address lookup and dump the
results to the screen:

.. code-block:: python

    import getdns, pprint, sys
    
    def main():
        if len(sys.argv) != 2:
            print "Usage: {0} hostname".format(sys.argv[0])
            sys.exit(1)
    
        ctx = getdns.Context()
        extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }
        results = ctx.address(name=sys.argv[1], extensions=extensions)
        if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
            sys.stdout.write("Addresses: ")
            
            for addr in results["just_address_answers"]:
                print " {0}".format(addr["IPSTRING"])
            sys.stdout.write("\n\n")
            print "Entire results tree: "
            pprint.pprint(results)
        if results["status"] == getdns.GETDNS_RESPSTATUS_NO_NAME:
            print "{0} not found".format(sys.argv[1])
    
    
    if __name__ == "__main__":
        main()


In this example, we do a DNSSEC query and check the response:

.. code-block:: python

    import getdns, sys
    
    dnssec_status = {
        "GETDNS_DNSSEC_SECURE" : 400,
        "GETDNS_DNSSEC_BOGUS" : 401,
        "GETDNS_DNSSEC_INDETERINATE" : 402,
        "GETDNS_DNSSEC_INSECURE" : 403,
        "GETDNS_DNSSEC_NOT_PERFORMED" : 404
    }
    
    
    def dnssec_message(value):
        for message in dnssec_status.keys():
            if dnssec_status[message] == value:
                return message
    
    def main():
        if len(sys.argv) != 2:
            print "Usage: {0} hostname".format(sys.argv[0])
            sys.exit(1)
    
        ctx = getdns.Context()
        extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE,
                       "dnssec_return_status" : getdns.GETDNS_EXTENSION_TRUE }
        results = ctx.address(name=sys.argv[1], extensions=extensions)
        if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
            sys.stdout.write("Addresses: ")
            for addr in results["just_address_answers"]:
                print " {0}".format(addr["IPSTRING"])
            sys.stdout.write("\n")
    
            for result in results["replies_tree"]:
                if "dnssec_status" in result.keys():
                    print "{0}: dnssec_status: {1}".format(result["canonical_name"],
                                                           dnssec_message(result["dnssec_status"]))
    
        if results["status"] == getdns.GETDNS_RESPSTATUS_NO_NAME:
            print "{0} not found".format(sys.argv[1])
    
    
    if __name__ == "__main__":
        main()
    

Known issues
============

* "userarg" currently only accepts a string.  This will be
  changed in a future release, to take arbitrary data types

* the "dns_transport" attribute is settable and readable but
  has no effect, as the underlying library does not
  currently support TCP


    
Contents:

.. toctree::
   :maxdepth: 1

   functions
   response



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

