:mod:`getdns` exceptions
=============================

.. module:: getdns
   :synopsis: getdns exception description and explanation
.. sectionauthor:: Melinda Shore <melinda.shore@nomountain.net>


getdns exceptions
-----------------

.. py:exception:: getdns.error

   getdns will throw an exception, ``getdns.error``, under
   certain conditions.  Those conditions include:

   * a required parameter having a bad value
   * a badly-formed domain name in the query
   * a bad ``Context()`` object
   * a failed ``Context()`` update
   * an out-of-bounds error for a getdns data structure
   * requesting an extension that doesn't exist
   * requesting DNSSEC validation while using stub
     resolution

Please note that a successful return from a getdns method
does `not` indicate that the query returned the records
being requested, but rather that the query is formed
correctly and has been submitted to the DNS.  A getdns
exception is typically the result of a coding error.

getdns will set the exception message to a diagnostic
string, which may be examined for help in resolving the
error.

Example
-------

::

 import getdns, sys
 
 c = getdns.Context()
 try:
     results = c.address('www.example.com', foo='bar')
 except getdns.error, e:
     print(str(e))
     sys.exit(1)


This will result in "A required parameter had an invalid
value" being printed to the screen.
