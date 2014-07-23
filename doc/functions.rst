:mod:`getdns` reference
==================================

.. module:: getdns
   :synopsis: getdns objects, methods, and attributes
.. sectionauthor:: Melinda Shore <melinda.shore@nomountain.net>



getdns contexts
---------------

This section describes the *getdns* Context object, as well as its
as its methods and attributes.

.. py:class:: Context([set_from_os])

   Creates a *context*, an opaque object which describes the
   environment within which a DNS query executes.  This
   includes namespaces, root servers, resolution types, and
   so on.  These are accessed programmatically through the
   attributes described below.

   Context() takes one optional constructor argument.
   ``set_from_os`` is an integer and may take the value either
   0 or 1.  If 1, which most developers will want, getdns
   will populate the context with default values for the
   platform on which it's running.

  The :class:`Context` class has the following public read/write attributes:

  .. py:attribute:: resolution_type

   Specifies whether DNS queries are performed with
   nonrecursive lookups or as a stub resolver. The value is
   either ``getdns.GETDNS_RESOLUTION_RECURSING`` or
   ``getdns.GETDNS_RESOLUTION_STUB``.

   If an implementation of this API is only able to act as a
   recursive resolver, setting `resolution_type`
   to ``getdns.GETDNS_RESOLUTION_STUB`` will throw an exception.

  .. py:attribute:: namespaces

   The `namespaces` attribute takes an ordered list of
   namespaces that will be queried. (*Important: this context
   setting is ignored for the getdns.general() function;
   it is used for the other
   functions.*) The allowed values are
   ``getdns.GETDNS_NAMESPACE_DNS``, ``getdns.GETDNS_NAMESPACE_LOCALNAMES``, 
   ``getdns.GETDNS_NAMESPACE_NETBIOS``,
   ``getdns.GETDNS_NAMESPACE_MDNS``, and ``getdns.GETDNS_NAMESPACE_NIS``. When a
   normal lookup is done, the API does the lookups in the
   order given and stops when it gets the first result; a
   different method with the same result would be to run the
   queries in parallel and return when it gets the first
   result. Because lookups might be done over different
   mechanisms because of the different namespaces, there can
   be information leakage that is similar to that seen with
   POSIX *getaddrinfo()*. The default is determined by the OS.

  .. py:attribute:: dns_transport

   Specifies what transport is used for DNS lookups. The
   value must be one of ``getdns.GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP``,
   ``getdns.GETDNS_TRANSPORT_UDP_ONLY``, ``getdns.GETDNS_TRANSPORT_TCP_ONLY``, or
   ``getdns.GETDNS_TRANSPORT_TCP_ONLY_KEEP_CONNECTIONS_OPEN``. 

  .. py:attribute:: limit_outstanding_queries

   Specifies `limit` (an integer value) on the number of outstanding DNS
   queries. The API will block itself from sending more
   queries if it is about to exceed this value, and instead
   keep those queries in an internal queue. The a value of 0
   indicates that the number of outstanding DNS queries is unlimited.

  .. py:attribute:: follow_redirects

   Specifies whether or not DNS queries follow
   redirects.  The value must be one of ``getdns.GETDNS_REDIRECTS_FOLLOW`` for
   normal following of redirects though CNAME and DNAME; or
   ``getdns.GETDNS_REDIRECTS_DO_NOT_FOLLOW`` to cause any lookups that
   would have gone through CNAME and DNAME to return the
   CNAME or DNAME, not the eventual target.

  .. py:attribute:: dns_root_servers

   The value of `dns_root_servers` is a list of dictionaries
   containing addresses to be used for looking up top-level
   domains.  Each dict in the list contains two key-value
   pairs:
  
   * address_data: a string representation of an IPv4 or
     IPv6 address
   * address_type: either the string "IPv4" or "IPv6"

   For example, the addresses list could look like

   >>> addrs = [ { 'address_data': '2001:7b8:206:1::4:53', 'address_type': 'IPv6' },
   ...         { 'address_data': '65.22.9.1', 'address_type': 'IPv4' } ]
   >>> mycontext.dns_root_servers = addrs

  .. py:attribute:: append_name

   Specifies whether to append a suffix to the query string
   before the API starts resolving a name. Its value must be
   one of
   ``getdns.GETDNS_APPEND_NAME_ALWAYS``,
   ``getdns.GETDNS_APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE``,
   ``getdns.GETDNS_APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE``,
   or ``getdns.GETDNS_APPEND_NAME_NEVER``. This controls whether or not
   to append the suffix given by :attr:`suffix`.

  .. py:attribute:: suffix

   Its value is a list of strings to be appended based on
   :attr:`append_name`.  The list elements must
   follow the rules in :rfc:`4343#section-2.1`

  .. py:attribute:: dnssec_trust_anchors

   Its value is a list of DNSSEC trust anchors, expressed as
   RDATAs from DNSKEY resource records.

  .. py:attribute:: dnssec_allowed_skew

   Its value is the number of seconds of skew that is
   allowed in either direction when checking an RRSIG's
   Expiration and Inception fields. The default is 0.

  .. py:attribute:: edns_maximum_udp_payload_size

   Its value must be an integer between 512 and 65535,
   inclusive.  The default is 512.

  .. py:attribute:: edns_extended_rcode

   Its value must be an integer between 0 and 255, inclusive.
   The default is 0.

  .. py:attribute:: edns_version

   Its value must be an integer between 0 and 255, inclusive.
   The default is 0.

  .. py:attribute:: edns_do_bit

   Its value must be an integer valued either 0 or 1.  The default is 0.

  .. py:attribute:: timeout
   
   Its value must be an integer specifying a timeout for a query, expressed 
   in milliseconds.

  .. py:attribute:: upstream_recursive_servers

   A list of dicts defining where a stub resolver will send queries.
   Each dict in the list contains at least two names: address_type
   (whose value is a bindata; it is currently either "IPv4" or "IPv6")
   and address_data (whose value is a bindata). It might also contain
   port to specify which port to use to contact these DNS servers; the
   default is 53. If the stub and a recursive resolver both support
   TSIG (RFC 2845), the upstream_list entry can also contain
   tsig_algorithm (a bindata) that is the name of the TSIG hash
   algorithm, and tsig_secret (a bindata) that is the TSIG key.

  The :class:`Context` class includes public methods to execute a DNS query, as well as a
  method to return the entire set of context attributes as a Python dictionary.  :class:`Context`
  methods are described below:


  .. py:method:: general(name, request_type, [extensions], [userarg], [transaction_id], [callback])

   ``Context.general()`` is used for looking up any type of
   DNS record.  The keyword arguments are:

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

  .. py:method:: address(name, [extensions], [userarg], [transaction_id], [callback])

   There are three critical differences between
   ``Context.address()`` and ``Context.general()`` beyond the missing
   *request_type* argument:

   * In ``getdns.address()``, the name argument can only take a host name.
   * You do not need to include a ``return_both_v4_and_v6`` extension with the call in ``getdns.address()``; it will
     always return both IPv4 and IPv6 addresses.
   * ``Context.address()`` always uses all of namespaces from the
     context (to better emulate getaddrinfo()), while ``Context.general()`` only uses the DNS namespace.

  .. py:method:: hostname(name [, extensions], [userarg], [transaction_id], [callback])

   The address is given as a dictionary. The dictionary must
   have two names: 

   * ``address_type``: must be a string matching either "IPv4"
     or "IPv6"
   * ``address_type``: a string representation of an IPv4 or
     IPv6 IP address

  .. py:method:: service(name [, extensions], [userarg], [transaction_id], [callback])

   ``name`` must be a domain name for an SRV lookup.  The call
   returns the relevant SRV information for the name

  .. py:method:: get_api_information()

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

Extensions
----------

Extensions are Python dictionaries, with the keys being the names of the
extensions.  The definition of each extension describes the values that
may be assigned to that extension.  For most extensions it is a Boolean,
and since the default value is "False" it will most often take the value
``getdns.GETDNS_EXTENSION_TRUE``.

The extensions currently supported by :py:mod:`getdns` are:

   * ``dnssec_return_status``
   * ``dnssec_return_only_secure``
   * ``dnssec_return_validation_chain``
   * ``return_both_v4_and_v6``
   * ``add_opt_parameters``
   * ``add_warning_for_bad_dns``
   * ``specify_class``
   * ``return_call_debugging``

Extensions for DNSSEC
^^^^^^^^^^^^^^^^^^^^^

If an application wants the API to do DNSSEC validation for
a request, it must set one or more DNSSEC-related
extensions. Note that the default is for none of these
extensions to be set and the API will not perform
DNSSEC validation. Note that getting DNSSEC results can take longer in
a few circumstances.

To return the DNSSEC status for each DNS record in the
``replies_tree`` list, use the ``dnssec_return_status``
extension. Set the extension's value to
``getdns.GETDNS_EXTENSION_TRUE`` to cause the returned status to have
the name ``dnssec_status`` added to the other names in
the record's dictionary ("header", "question", and so on). The
potential values for that name are ``getdns.GETDNS_DNSSEC_SECURE``,
``getdns.GETDNS_DNSSEC_BOGUS``, ``getdns.GETDNS_DNSSEC_INDETERMINATE``, and
``getdns.GETDNS_DNSSEC_INSECURE``. 

If instead of returning the status, you want to only see
secure results, use the ``dnssec_return_only_secure``
extension. The extension's value is set to
``getdns.GETDNS_EXTENSION_TRUE`` to cause only records that the API can
validate as secure with DNSSEC to be returned in the
``replies_tree`` and ``replies_full lists``. No additional names are
added to the dict of the record; the change is that some
records might not appear in the results. When this context
option is set, if the API receives DNS replies but none are
determined to be secure, the error code at the top level of
the ``response`` object is ``getdns.GETDNS_RESPSTATUS_NO_SECURE_ANSWERS``.

Applications that want to do their own validation will want
to have the DNSSEC-related records for a particular
response. Use the ``dnssec_return_validation_chain``
extension. Set the extension's value to
``getdns.GETDNS_EXTENSION_TRUE`` to cause a set of additional
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
error of ``getdns.GETDNS_RETURN_DNSSEC_WITH_STUB_DISALLOWED``.

Returning both IPv4 and IPv6 responses
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Many applications want to get both IPv4 and IPv6 addresses
in a single call so that the results can be processed
together. The :meth:`address`
method is able to do this automatically. If you are
using the :meth:`general` method,
you can enable this with the ``return_both_v4_and_v6``
extension. The extension's value must be set to
``getdns.GETDNS_EXTENSION_TRUE`` to cause the results to be the lookup
of either A or AAAA records to include any A and AAAA
records for the queried name (otherwise, the extension does
nothing). These results are expected to be usable with Happy
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
``getdns.GETDNS_EXTENSION_TRUE`` to cause each reply in the
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
``getdns.GETDNS_EXTENSION_TRUE`` to add the name ``call_debugging`` (a
list) to the top level of the ``response`` object. Each member
of the list is a dict that represents one call made for the
call to the API. Each member has the following names:

   * ``query_name`` is the name that was sent
   * ``query_type`` is the type that was queried for
   * ``query_to`` is the address to which the query was sent
   * ``start_time`` is the time the query started in milliseconds since the epoch, represented as an integer
   * ``end_time`` is the time the query was received in milliseconds since the epoch, represented as an integer
   * ``entire_reply`` is the entire response received
   * ``dnssec_result`` is the DNSSEC status, or ``getdns.GETDNS_DNSSEC_NOT_PERFORMED`` if DNSSEC validation was not performed
