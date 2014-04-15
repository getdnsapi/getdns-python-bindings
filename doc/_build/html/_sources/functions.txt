:mod:`pygetdns` function reference
==================================

.. module:: getdns
   :synopsis: getdns functions and constants
.. sectionauthor:: Melinda Shore <melinda.shore@nomountain.net>



getdns contexts
---------------

This section describes the functions used to create, read,
and manipulate *getdns* context objects.

.. py:function:: context_create([set_from_os])

   Creates a *context*, an opaque object which describes the
   environment within which a DNS query executes.  This
   includes namespaces, root servers, resolution types, and
   so on.  These are accessed programmatically through the
   getter and setters described below.

   context_create() takes one optional argument.
   *set_from_os* is an integer and may take the value either
   0 or 1.  If 1, which most developers will want, getdns
   will populate the context with default values for the
   platform on which it's running.

   *context_create* returns a context object.

.. py:function:: context_set_resolution_type(context, value)

   Specifies whether DNS queries are performed with
   nonrecursive lookups or as a stub resolver. The value is
   either **getdns.GETDNS_RESOLUTION_RECURSING** or
   **getdns.GETDNS_RESOLUTION_STUB**.

   If an implementation of this API is only able to act as a
   recursive resolver, a call to
   getdns.getdns_context_set_resolution_type(somecontext,
   getdns.GETDNS_RESOLUTION_STUB) will throw an exception.

.. py:function:: context_set_namespaces(context, count, namespaces)

   The namespaces list contains an ordered list of
   namespaces that will be queried. (*Important: this context
   setting is ignored for the getdns.general() function;
   it is used for the other
   functions.*) The allowed values are
   **getdns.GETDNS_NAMESPACE_DNS**, **getdns.GETDNS_NAMESPACE_LOCALNAMES**, 
   **getdns.GETDNS_NAMESPACE_NETBIOS**,
   **getdns.GETDNS_NAMESPACE_MDNS**, and **getdns.GETDNS_NAMESPACE_NIS**. When a
   normal lookup is done, the API does the lookups in the
   order given and stops when it gets the first result; a
   different method with the same result would be to run the
   queries in parallel and return when it gets the first
   result. Because lookups might be done over different
   mechanisms because of the different namespaces, there can
   be information leakage that is similar to that seen with
   POSIX *getaddrinfo()*. The default is determined by the OS.

.. py:function:: context_set_dns_transport(context, value)

   Specifies what transport is used for DNS lookups. The
   value must be one of **getdns.GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP**,
   **getdns.GETDNS_TRANSPORT_UDP_ONLY**, **getdns.GETDNS_TRANSPORT_TCP_ONLY**, or
   **getdns.GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN**. 

.. py:function:: context_set_limit_outstanding_queries(context, limit)

   Specifies *limit* (an integer value) on the number of outstanding DNS
   queries. The API will block itself from sending more
   queries if it is about to exceed this value, and instead
   keep those queries in an internal queue. The a value of 0
   indicates that the number of outstanding DNS queries is unlimited.

.. py:function:: context_set_follow_redirects(context, value)

   Specifies whether or not DNS queries follow
   redirects. *value* must be one of **getdns.GETDNS_REDIRECTS_FOLLOW** for
   normal following of redirects though CNAME and DNAME; or
   **getdns.GETDNS_REDIRECTS_DO_NOT_FOLLOW** to cause any lookups that
   would have gone through CNAME and DNAME to return the
   CNAME or DNAME, not the eventual target.

.. py:function:: context_set_dns_root_servers(context, addresses)

   The *addresses* argument is a list of dictionaries
   containing addresses to be used for looking up top-level
   domains.  Each dict in the list contains two key-value
   pairs:
  
   * address_data: a string representation of an IPv4 or
     IPv6 address
   * address_type: either the string "IPv4" or "IPv6"

   For example, the addresses list could look like

   >>> addresses = [ { 'address_data': '2001:7b8:206:1::4:53', 'address_type': 'IPv6' },
   ...             { 'address_data': '65.22.9.1', 'address_type': 'IPv4' } ]

.. py:function:: context_set_append_name(context, value)

   Specifies whether to append a suffix to the query string
   before the API starts resolving a name. *value* must be
   one of
   **getdns.GETDNS_APPEND_NAME_ALWAYS**,
   **getdns.GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE**,
   **getdns.GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE**,
   or **getdns.GETDNS_APPEND_NAME_NEVER**. This controls whether or not
   to append the suffix given by *getdns_context_set_suffix*.

.. py:function:: context_set_suffix(context, value)

   *value* is a list of strings to be appended based on
   *getdns.context_set_append_name*.  The list elements must
   follow the rules in :rfc:`4343#section-2.1`

.. py:function:: context_set_dnssec_trust_anchors(context, value)

   *value* is a list of DNSSEC trust anchors, expressed as
   RDATAs from DNSKEY resource records.

.. py:function:: context_set_dnssec_allowed_skew(context, value)

   The value is the number of seconds of skew that is
   allowed in either direction when checking an RRSIG's
   Expiration and Inception fields. The default is 0.

.. py:function:: context_set_edns_maximum_udp_payload_size(context, value)

   *value* must be an integer between 512 and 65535,
   inclusive.  The default is 512.

.. py:function:: context_set_edns_extended_rcode(context, value)

   *value* must be an integer between 0 and 255, inclusive.
   The default is 0.

.. py:function:: context_set_edns_version(context, value)

   *value* must be an integer between 0 and 255, inclusive.
   The default is 0.

.. py:function:: context_set_edns_do_bit(context, value)

   *value* must be either 0 or 1.  The default is 0

.. py:function:: context_get_api_information(context)

   Retrieves context information.  The information is
   returned as a Python dictionary with the following keys:

   * ``version_string``
   * ``implementation_string``
   * ``resolver_type``
   * ``all_context``

   ``all_context`` is a dictionary containing the following keys:

   * ``append_name``
   * ``dns_transport``
   * ``dnssec_allowed_skew``
   * ``edns_do_bit``
   * ``edns_extended_rcode``
   * ``edns_maximum_udp_payload_size``
   * ``edns_version``
   * ``follow_redirects``
   * ``limit_outstanding_queries``
   * ``namespaces``
   * ``suffix``
   * ``timeout``
   * ``upstream_recursive_servers``


getdns queries
--------------

This section describes the functions used to execute DNS
queries using *getdns*.

.. py:function:: general(context, name, request_type, [extensions], [userarg], [transaction_id], [callback])

   ``getdns.general()`` is used for looking up any type of
   DNS record.  The keyword arguments are:

   * ``context``: A context, as described above.
   * ``name``: a representation of the query term; usually a
     string but must be a dict (as described below) in the
     case of a PTR record lookup
   * ``request_type``: a DNS RR type as a getdns constant
     (listed here)
   * ``extensions``: optional.  A dictionary containing
     attribute/value pairs, as described below
   * ``userarg``: optional.  A string containing arbitrary user data;
     this is opaque to getdns
   * ``transaction_id``: optional.  An integer.  
   * ``callback``: optional.  This is a function name.  If it is present the query
     will be performed asynchronously (described below).

.. py:function:: address(context, name, [extensions], [userarg], [transaction_id], [callback] 

   There are three critical differences between
   ``getdns.address()`` and ``getdns.general()`` beyond the missing
   *request_type* argument:

   * In ``getdns.address()``, the name argument can only take a host name.
   * You do not need to include a ``return_both_v4_and_v6`` extension with the call in ``getdns.address()``; it will
     always return both IPv4 and IPv6 addresses.
   * ``getdns.address()`` always uses all of namespaces from the
     context (to better emulate getaddrinfo()), while ``getdns.general()`` only uses the DNS namespace.


.. py:function:: hostname(context, name, [extensions], [userarg], [transaction_id], [callback])

   The address is given as a dictionary. The dictionary must
   have two names: 

   * ``address_type``: must be a string matching either "IPv4"
     or "IPv6"
   * ``address_type``: a string representation of an IPv4 or
     IPv6 IP address

.. py:function:: service(context, name, [extensions], [userarg], [transaction_id], [callback])

   ``name`` must be a domain name for an SRV lookup.  The call
   returns the relevant SRV information for the name


getdns callback functions
-------------------------

An asynchronous call to *getdns* functions (signaled by the presence of
a callback argument to the query functions) typically returns
before any network or file I/O occurs. After the API
marshalls all the needed information, it calls the callback
function that was passed by the application. The callback
function might be called at any time, even before the
calling function has returned. The API guarantees that the
callback will be called exactly once unless the calling
function returned an error, in which case the callback
function is never called.

The *getdns* callback function takes the parameters described below:

   *  ``context``: the context that was used by the calling function
   *  ``callback_type``: supplies the reason for the callback (see below)
   *  ``response``: a Python dictionary containing the response data, 
      described below
   *  ``userarg``: identical to the userarg passed to the calling function
   *  ``transaction_id``: the transaction identifier that was assigned by the 
      calling function

For example, the code for an asynchronous query with a callback might 
look like this

   >>> import getdns
   >>> import pprint
   >>> def process_response(c, type,  resp, userarg, tid):
   ...    print 'In callback ... '
   ...    pprint.pprint(resp)
   >>> c = getdns.context_create()
   >>> getdns.address(context=c, name='www.example.com', callback='process_response')

The following are the possible values for callback_type:

.. py:data:: GETDNS_CALLBACK_COMPLETE

The response has the requested data in it

.. py:data:: GETDNS_CALLBACK_CANCEL

The calling program cancelled the callback; response is NULL

.. py:data:: GETDNS_CALLBACK_TIMEOUT

The requested action timed out; response is NULL

.. py:data:: GETDNS_CALLBACK_ERROR

The requested action had an error; response is NULL

Extensions
----------

Extensions are Python dictionaries, with the keys being the names of the
extensions.  The definition of each extension describes the values that
may be assigned to that extension.  For most extensions it is a Boolean,
and since the default value is "False" it will most often take the value
**getdns.GETDNS_EXTENSION_TRUE**.

The extensions currently supported by *getdns* are:

   * dnssec_return_status
   * dnssec_return_only_secure
   * dnssec_return_validation_chain
   * return_both_v4_and_v6
   * add_opt_parameters
   * add_warning_for_bad_dns
   * specify_class
   * return_call_debugging

Extensions for DNSSEC
^^^^^^^^^^^^^^^^^^^^^

If an application wants the API to do DNSSEC validation for
a request, it must set one or more DNSSEC-related
extensions. Note that the default is for none of these
extensions to be set and the API will not perform
DNSSEC. Note that getting DNSSEC results can take longer in
a few circumstances.

To return the DNSSEC status for each DNS record in the
``replies_tree`` list, use the ``dnssec_return_status``
extension. Set the extension's value to
**getdns.GETDNS_EXTENSION_TRUE** to cause the returned status to have
the name ``dnssec_status`` added to the other names in
the record's dictionary ("header", "question", and so on). The
values for that name are **getdns.GETDNS_DNSSEC_SECURE**,
**getdns.GETDNS_DNSSEC_BOGUS**, **getdns.GETDNS_DNSSEC_INDETERMINATE**, and
**getdns.GETDNS_DNSSEC_INSECURE**. 

If instead of returning the status, you want to only see
secure results, use the ``dnssec_return_only_secure``
extension. The extension's value is set to
**getdns.GETDNS_EXTENSION_TRUE** to cause only records that the API can
validate as secure with DNSSEC to be returned in the
``replies_tree`` and ``replies_full lists``. No additional names are
added to the dict of the record; the change is that some
records might not appear in the results. When this context
option is set, if the API receives DNS replies but none are
determined to be secure, the error code at the top level of
the ``response`` object is **getdns.GETDNS_RESPSTATUS_NO_SECURE_ANSWERS**.

Applications that want to do their own validation will want
to have the DNSSEC-related records for a particular
response. Use the ``dnssec_return_validation_chain``
extension. The extension's value is set to
**getdns.GETDNS_EXTENSION_TRUE** to cause a set of additional
DNSSEC-related records needed for validation to be returned
in the ``response object``. This set comes as ``validation_chain``
(a list) at the top level of the ``response`` object. This list
includes all resource record dicts for all the resource
records (DS, DNSKEY and their RRSIGs) that are needed to
perform the validation from the root up.

If a request is using a context in which stub resolution is
set, and that request also has any of the
``dnssec_return_status``, ``dnssec_return_only_secure``, or
``dnssec_return_validation_chain`` extensions specified, the API
will not perform the request and will instead return an
error of **getdns.GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED**.

Returning both IPv4 and IPv6 responses
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Many applications want to get both IPv4 and IPv6 addresses
in a single call so that the results can be processed
together. The ``getdns.address()``
function is able to do this automatically. If you are
using the ``getdns.general()`` function,
you can enable this with the ``return_both_v4_and_v6``
extension. The extension's value must be set to
**getdns.GETDNS_EXTENSION_TRUE** to cause the results to be the lookup
of either A or AAAA records to include any A and AAAA
records for the queried name (otherwise, the extension does
nothing). These results are expected to be used with Happy
Eyeballs systems that will find the best socket for an
application.

Setting up OPT resource records
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For lookups that need an **OPT** resource record in the
Additional Data section, use the ``add_opt_parameters``
extension. The extension's value (a dict) contains the
parameters; these are described in more detail in
:rfc:`2671`. They are:

   * ``maximum_udp_payload_size``: an integer between 512 and 65535 inclusive.
     If not specified it defaults to the value in the getdns context.
   * ``extended_rcode``: an integer between 0 and 255 inclusive.  If not
     specified it defaults to the value in the getdns context.
   * ``version``: an integer betwen 0 and 255 inclusive.  If not specified it
     defaults to 0.
   * ``do_bit``: must be either 0 or 1.  If not specified it defaults to
     the value in the getdns context.
   * ``options``: a list containing dictionaries for each option to be specified.
     Each dictionary contains two keys: ``option_code`` (an integer) and ``option_data``
     (in the form appropriate for that option code).

It is very important to note that the OPT resource record
specified in the ``add_opt_parameters extension`` might not be
the same the one that the API sends in the query. For
example, if the application also includes any of the DNSSEC
extensions, the API will make sure that the OPT resource
record sets the resource record appropriately, making the
needed changes to the settings from the ``add_opt_parameters``
extension.

Getting Warnings for Responses that Violate the DNS Standard
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To receive a warning if a particular response violates some
parts of the DNS standard, use the ``add_warning_for_bad_dns``
extension. The extension's value is set to
**getdns.GETDNS_EXTENSION_TRUE** to cause each reply in the
``replies_tree`` to contain an additional name, ``bad_dns`` (a
list). The list is zero or more values that indicate types of
bad DNS found in that reply. The list of values is:

.. py:data:: GETDNS_BAD_DNS_CNAME_IN_TARGET

A DNS query type that does not allow a target to be a CNAME pointed to a CNAME

.. py:data:: GETDNS_BAD_DNS_ALL_NUMERIC_LABEL

One or more labels in a returned domain name is all-numeric; this is not legal for a hostname

.. py:data:: GETDNS_BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE

A DNS query for a type other than CNAME returned a CNAME response

Using other class types
^^^^^^^^^^^^^^^^^^^^^^^

The vast majority of DNS requests are made with the Internet
(IN) class. To make a request in a different DNS class, use,
the ``specify_class extension``. The extension's value (an int)
contains the class number. Few applications will ever use
this extension.

Extensions relating to the API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An application might want to see debugging information for
queries, such as the length of time it takes for each query
to return to the API.  Use the ``return_call_debugging``
extension. The extension's value is set to
**getdns.GETDNS_EXTENSION_TRUE** to add the name ``call_debugging`` (a
list) to the top level of the ``response`` object. Each member
of the list is a dict that represents one call made for the
call to the API. Each member has the following names:

   * ``query_name`` is the name that was sent
   * ``query_type`` is the type that was queried for
   * ``query_to`` is the address to which the query was sent
   * ``start_time`` is the time the query started in milliseconds since the epoch, represented as an integer
   * ``end_time`` is the time the query was received in milliseconds since the epoch, represented as an integer
   * ``entire_reply`` is the entire response received
   * ``dnssec_result`` is the DNSSEC status, or **getdns.GETDNS_DNSSEC_NOT_PERFORMED** if DNSSEC validation was not performed
