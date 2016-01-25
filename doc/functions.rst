:mod:`getdns` reference
==================================

.. module:: getdns
   :synopsis: getdns objects, methods, and attributes
.. sectionauthor:: Melinda Shore <melinda.shore@nomountain.net>



getdns contexts
---------------

This section describes the *getdns* Context object, as well
as its
as its methods and attributes.

.. py:class:: Context([set_from_os])

   Creates a *context*, an opaque object which describes the
   environment within which a DNS query executes.  This
   includes namespaces, root servers, resolution types, and
   so on.  These are accessed programmatically through the
   attributes described below.

   Context() takes one optional constructor argument.
   ``set_from_os`` is an integer and may take the value
   either
   0 or 1.  If 1, which most developers will want, getdns
   will populate the context with default values for the
   platform on which it's running.

  The :class:`Context` class has the following public
  read/write attributes:

  .. py:attribute:: append_name

   Specifies whether to append a suffix to the query string
   before the API starts resolving a name. Its value must be
   one of
   ``getdns.APPEND_NAME_ALWAYS``,
   ``getdns.APPEND_NAME_ONLY_TO_SINGLE_LABEL_AFTER_FAILURE``,
   ``getdns.APPEND_NAME_ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE``,
   or ``getdns.APPEND_NAME_NEVER``. This controls whether or
   not
   to append the suffix given by :attr:`suffix`.

  .. py:attribute:: dns_root_servers

   The value of `dns_root_servers` is a list of dictionaries
   containing addresses to be used for looking up top-level
   domains.  Each dict in the list contains two key-value
   pairs:
  
   * address_data: a string representation of an IPv4 or
     IPv6 address
   * address_type: either the string "IPv4" or "IPv6"

   For example, the addresses list could look like

   >>> addrs = [ { 'address_data': '2001:7b8:206:1::4:53',
       'address_type': 'IPv6' },
   ...         { 'address_data': '65.22.9.1',
       'address_type': 'IPv4' } ]
   >>> mycontext.dns_root_servers = addrs

  .. py:attribute:: dns_transport_list

   An ordered list of transport options to be used for DNS
   lookups, ordered by preference (first choice as list
   element 0, second as list element 1, and so on).  The
   possible values are ``getdns.TRANSPORT_UDP``,
   ``getdns.TRANSPORT_TCP``, and ``getdns.TRANSPORT_TLS``.

  .. py:attribute:: dnssec_allowed_skew

   Its value is the number of seconds of skew that is
   allowed in either direction when checking an RRSIG's
   Expiration and Inception fields. The default is 0.

  .. py:attribute:: dnssec_trust_anchors

   Its value is a list of DNSSEC trust anchors, expressed as
   RDATAs from DNSKEY resource records.

  .. py:attribute:: edns_client_subnet_private

   May be set to 0 or 1.  When 1, requests upstreams not to
   reveal query's originating network.

  .. py:attribute:: edns_do_bit

   Its value must be an integer valued either 0 or 1.  The
   default is 0.

  .. py:attribute:: edns_extended_rcode

   Its value must be an integer between 0 and 255,
   inclusive.
   The default is 0.

  .. py:attribute:: edns_maximum_udp_payload_size

   Its value must be an integer between 512 and 65535,
   inclusive.  The default is 512.

  .. py:attribute:: edns_version

   Its value must be an integer between 0 and 255,
   inclusive.
   The default is 0.

  .. py:attribute:: follow_redirects

   Specifies whether or not DNS queries follow
   redirects.  The value must be one of
   ``getdns.REDIRECTS_FOLLOW`` for
   normal following of redirects though CNAME and DNAME; or
   ``getdns.REDIRECTS_DO_NOT_FOLLOW`` to cause any lookups
   that
   would have gone through CNAME and DNAME to return the
   CNAME or DNAME, not the eventual target.

  .. py:attribute:: idle_timeout

   The idle timeout for TCP connections.

  .. py:attribute:: implementation_string

   A string describing the implementation of the underlying
   getdns library, retrieved from
   libgetdns.  Currently "https://getdnsapi.net"

  .. py:attribute:: limit_outstanding_queries

   Specifies `limit` (an integer value) on the number of
   outstanding DNS
   queries. The API will block itself from sending more
   queries if it is about to exceed this value, and instead
   keep those queries in an internal queue. The a value of 0
   indicates that the number of outstanding DNS queries is
   unlimited.

  .. py:attribute:: namespaces

   The `namespaces` attribute takes an ordered list of
   namespaces that will be queried. (*Important: this
   context
   setting is ignored for the getdns.general() function;
   it is used for the other
   functions.*) The allowed values are
   ``getdns.NAMESPACE_DNS``,
   ``getdns.NAMESPACE_LOCALNAMES``, 
   ``getdns.NAMESPACE_NETBIOS``,
   ``getdns.NAMESPACE_MDNS``, and
   ``getdns.NAMESPACE_NIS``. When a
   normal lookup is done, the API does the lookups in the
   order given and stops when it gets the first result; a
   different method with the same result would be to run the
   queries in parallel and return when it gets the first
   result. Because lookups might be done over different
   mechanisms because of the different namespaces, there can
   be information leakage that is similar to that seen with
   POSIX *getaddrinfo()*. The default is determined by the
   OS.

  .. py:attribute:: resolution_type

   Specifies whether DNS queries are performed with
   nonrecursive lookups or as a stub resolver. The value is
   either ``getdns.RESOLUTION_RECURSING`` or
   ``getdns.RESOLUTION_STUB``.

   If an implementation of this API is only able to act as a
   recursive resolver, setting `resolution_type`
   to ``getdns.RESOLUTION_STUB`` will throw an exception.

  .. py:attribute:: suffix

   Its value is a list of strings to be appended based on
   :attr:`append_name`.  The list elements must
   follow the rules in :rfc:`4343#section-2.1`

  .. py:attribute:: timeout
   
   Its value must be an integer specifying a timeout for a
   query, expressed 
   in milliseconds.

  .. py:attribute:: tls_authentication

   The mechanism to be used for authenticating the TLS
   server when using a TLS transport.  May be
   ``getdns.AUTHENTICATION_REQUIRED`` or
   ``getdns.AUTHENTICATION_NONE``.
   (getdns.AUTHENTICATION_HOSTNAME remains as an alias for
   getdns.AUTHENTICATION_REQUIRED but is deprecated and will
   be removed in a future release)

  .. py:attribute:: tls_query_padding_blocksize

   Optional padding blocksize for queries when using TLS.
   Used to
   increase the difficulty for observers to guess traffic
   content.

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

   There is also now support for pinning an upstream's
   certificate's public keys, with pinsets (when using TLS
   for transport.  Add an element to the
   upstream_recursive_server list entry, called
   'tls_pubkey_pinset', which is a list of public key pins.
   (See the example code in our examples directory).
                    
  .. py:attribute:: version_string

    The libgetdns version, retrieved from the underlying
    getdns library.


  The :class:`Context` class includes public methods to execute a DNS query, as well as a
  method to return the entire set of context attributes as a Python dictionary.  :class:`Context`
  methods are described below:


  .. py:method:: general(name, request_type, [extensions], [userarg], [transaction_id], [callback])

   ``Context.general()`` is used for looking up any type of
   DNS record.  The keyword arguments are:

   * ``name``: a representation of the query term; usually a
     string but must be a dict (as described in ``Context.hostname()`` below) in the
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

   There are two critical differences between
   ``Context.address()`` and ``Context.general()`` beyond the missing
   *request_type* argument:

   * In ``Context.address()``, the name argument can only take a host name.
   * ``Context.address()`` always uses all of namespaces from the
     context (to better emulate getaddrinfo()), while ``Context.general()`` only uses the DNS namespace.

  .. py:method:: hostname(name [, extensions], [userarg], [transaction_id], [callback])

   The address is given as a dictionary. The dictionary must
   have two names: 

   * ``address_type``: must be a string matching either "IPv4"
     or "IPv6"
   * ``address_data``: a string representation of an IPv4 or
     IPv6 IP address

  .. py:method:: service(name [, extensions], [userarg], [transaction_id], [callback])

   ``name`` must be a domain name for an SRV lookup.  The call
   returns the relevant SRV information for the name

  .. py:method:: get_api_information()

   Retrieves context information.  The information is
   returned as a Python dictionary with the following keys:

   * ``version_string``
   * ``implementation_string``
   * ``resolution_type``
   * ``all_context``

   ``all_context`` is a dictionary containing the following keys:

   * ``append_name``
   * ``dns_transport``
   * ``dnssec_allowed_skew``
   * ``edns_do_bit``
   * ``edns_extended_rcode``
   * ``edns_version``
   * ``follow_redirects``
   * ``limit_outstanding_queries``
   * ``namespaces``
   * ``suffix``
   * ``timeout``
   * ``tls_authentication``
   * ``upstream_recursive_servers``

  .. py:method:: get_supported_attributes()

   Returns a list of the attributes supported by this
   Context object.

The ``getdns`` module has the following read-only attribute:

.. py:attribute:: __version__

   Specifies the version string for the getdns python module

Extensions
----------

Extensions are Python dictionaries, with the keys being the names of the
extensions.  The definition of each extension describes the values that
may be assigned to that extension.  For most extensions it is a Boolean,
and since the default value is "False" it will most often take the value
``getdns.EXTENSION_TRUE``.

The extensions currently supported by :py:mod:`getdns` are:

   * ``dnssec_return_status``
   * ``dnssec_return_only_secure``
   * ``dnssec_return_validation_chain``
   * ``return_both_v4_and_v6``
   * ``add_opt_parameters``
   * ``add_warning_for_bad_dns``
   * ``specify_class``
   * ``return_call_reporting``

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
``getdns.EXTENSION_TRUE`` to cause the returned status to have
the name ``dnssec_status`` added to the other names in
the record's dictionary ("header", "question", and so on). The
potential values for that name are ``getdns.DNSSEC_SECURE``,
``getdns.DNSSEC_BOGUS``, ``getdns.DNSSEC_INDETERMINATE``, and
``getdns.DNSSEC_INSECURE``. 

If instead of returning the status, you want to only see
secure results, use the ``dnssec_return_only_secure``
extension. The extension's value is set to
``getdns.EXTENSION_TRUE`` to cause only records that the API can
validate as secure with DNSSEC to be returned in the
``replies_tree`` and ``replies_full lists``. No additional names are
added to the dict of the record; the change is that some
records might not appear in the results. When this context
option is set, if the API receives DNS replies but none are
determined to be secure, the error code at the top level of
the ``response`` object is ``getdns.RESPSTATUS_NO_SECURE_ANSWERS``.

Applications that want to do their own validation will want
to have the DNSSEC-related records for a particular
response. Use the ``dnssec_return_validation_chain``
extension. Set the extension's value to
``getdns.EXTENSION_TRUE`` to cause a set of additional
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
error of ``getdns.RETURN_DNSSEC_WITH_STUB_DISALLOWED``.

Returning both IPv4 and IPv6 responses
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Many applications want to get both IPv4 and IPv6 addresses
in a single call so that the results can be processed
together. The :meth:`address`
method is able to do this automatically. If you are
using the :meth:`general` method,
you can enable this with the ``return_both_v4_and_v6``
extension. The extension's value must be set to
``getdns.EXTENSION_TRUE`` to cause the results to be the lookup
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

The ``client_subnet.py`` program in our example directory
shows how to pack and send an OPT record.

Getting Warnings for Responses that Violate the DNS Standard
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To receive a warning if a particular response violates some
parts of the DNS standard, use the ``add_warning_for_bad_dns``
extension. The extension's value is set to
``getdns.EXTENSION_TRUE`` to cause each reply in the
``replies_tree`` to contain an additional name, ``bad_dns`` (a
list). The list is zero or more values that indicate types of
bad DNS found in that reply. The list of values is:

.. py:data:: BAD_DNS_CNAME_IN_TARGET

A DNS query type that does not allow a target to be a CNAME pointed to a CNAME

.. py:data:: BAD_DNS_ALL_NUMERIC_LABEL

One or more labels in a returned domain name is all-numeric; this is not legal for a hostname

.. py:data:: BAD_DNS_CNAME_RETURNED_FOR_OTHER_TYPE

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
to return to the API.  Use the ``return_call_reporting``
extension. The extension's value is set to
``getdns.EXTENSION_TRUE`` to add the name ``call_reporting`` (a
list) to the top level of the ``response`` object. Each member
of the list is a dict that represents one call made for the
call to the API. Each member has the following names:

   * ``query_name`` is the name that was sent
   * ``query_type`` is the type that was queried for
   * ``query_to`` is the address to which the query was sent
   * ``start_time`` is the time the query started in milliseconds since the epoch, represented as an integer
   * ``end_time`` is the time the query was received in milliseconds since the epoch, represented as an integer
   * ``entire_reply`` is the entire response received
   * ``dnssec_result`` is the DNSSEC status, or ``getdns.DNSSEC_NOT_PERFORMED`` if DNSSEC validation was not performed


Asynchronous queries
^^^^^^^^^^^^^^^^^^^^

The getdns Python bindings support asynchronous queries, in
which a query returns immediately and a callback function is
invoked when the response data are returned.  The query
method interfaces are fundamentally the same, with a few
differences:

   * The query returns a transaction id.  That transaction
     id may be used to cancel future callbacks
   * The query invocation includes the name of a callback
     function.  For example, if you'd like to call the
     function "my_callback" when the query returns, an
     address lookup could look like

   >>> c = getdns.Context()
   >>> tid = c.address('www.example.org', callback=my_callback)

   * We've introduced a new ``Context`` method, called
     ``run``.  When your program is ready to check to see
     whether or not the query has returned, invoke the run()
     method on your context.  Note that we use the libevent
     asynchronous event library and an event_base is
     associated with a context.  So, if you have multiple
     outstanding events associated with a particular
     context, ``run`` will invoke all of those that are
     waiting and ready.

   * In previous releases the callback argument took the
     form of a literal string, but as of this release you
     may pass in the name of any Python runnable, without
     quotes.  The newer form is preferred.

The callback script takes four arguments: ``type``,
``result``, ``userarg``, and ``transaction_id.  The ``type``
argument contains the callback type, which may have one of
the following values:

   * ``getdns.CALLBACK_COMPLETE``: The query was successful
     and the results are contained in the ``result``
     argument
   * ``getdns.CALLBACK_CANCEL``: The callback was cancelled
     before the results were processed
   * ``getdns.CALLBACK_TIMEOUT``: The query timed out before
     the results were processed
   * ``getdns.CALLBACK_ERROR``: An unspecified error
     occurred

The ``result`` argument contains a result object, with the
query response

The ``userarg`` argument contains the optional user argument
that was passed to the query at the time it was invoked.

The ``transaction_id`` argument contains the transaction_id
associated with a particular query; this is the same
transaction id that was returned when the query was invoked.

This is an example callback function:

.. code-block:: python

    def cbk(type, result, userarg, tid):
        if type == getdns.CALLBACK_COMPLETE:
            status = result.status
            if status == getdns.RESPSTATUS_GOOD:
                for addr in result.just_address_answers:
                    addr_type = addr['address_type']
                    addr_data = addr['address_data']
                    print '{0}: {1} {2}'.format(userarg, addr_type, addr_data)
            elif status == getdns.RESPSTATUS_NO_SECURE_ANSWERS:
                print "{0}: No DNSSEC secured responses found".format(hostname)
            else:
                print "{0}: getdns.address() returned error: {1}".format(hostname, status)
        elif type == getdns.CALLBACK_CANCEL:
            print 'Callback cancelled'
        elif type == getdns.CALLBACK_TIMEOUT:
            print 'Query timed out'
        else:
            print 'Unknown error'


