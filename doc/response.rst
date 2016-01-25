:mod:`getdns` response data
=============================

.. module:: getdns
   :synopsis: getdns response data description and explanation
.. sectionauthor:: Melinda Shore <melinda.shore@nomountain.net>


Response data from queries
--------------------------

.. py:class:: Result()

   A getdns query (``Context.address()``, ``Context.hostname()``,
   ``Context.service()``, and ``Context.general()``) returns a
   Result object.  A Result object is only returned from a
   query and may not be instantiated by the programmer.  It
   is a read-only object.  Contents may not be overwritten
   or deleted.

  It has no methods but includes the following attributes:

  .. py:attribute:: status

   The ``status`` attribute contains the status code returned
   by the query.  Note that it may be the case that the
   query can be successful but there are no data matching
   the query parameters.  Programmers using this API will
   need to first check to see if the query itself was
   successful, then check for the records returned.

   The ``status`` attribute may have the following values:

   .. py:data:: getdns.RESPSTATUS_GOOD

    At least one response was returned

   .. py:data:: getdns.RESPSTATUS_NO_NAME

    Queries for the name yielded all negative responses

   .. py:data:: getdns.RESPSTATUS_ALL_TIMEOUT

    All queries for the name timed out

   .. py:data:: getdns.RESPSTATUS_NO_SECURE_ANSWERS

    The context setting for getting only secure responses was
    specified, and at least one DNS response was received, but
    no DNS response was determined to be secure through DNSSEC.

    .. py:data:: getdns.RESPSTATUS_ALL_BOGUS_ANSWERS

    The context setting for getting only secure responses
    was specified, and at least one DNS response was
    received, but all received responses for the requested
    name were bogus.

  .. py:attribute:: answer_type

   The ``answer_type`` attribute contains the type of data
   that are returned (i.e., the namespace).  The
   ``answer_type`` attribute may have the following values:
   
   .. py:data:: getdns.NAMETYPE_DNS

    Normal DNS (:rfc:`1035`)

   .. py:data:: getdns.NAMETYPE_WINS

    The WINS name service (some reference needed)

  .. py:attribute:: canonical_name

   The value of ``canonical_name`` is the name that the API used for its lookup. It is in FQDN presentation format.

  .. py:attribute:: just_address_answers

   If the call was :meth:`address`, the
   attribute 
   ``just_address_answers`` (a list) is non-null. The value of
   ``just_address_answers`` is a list that contains all of the A
   and AAAA records from the ``answer`` sections of any of the
   replies, in the order they appear in the replies. Each item
   in the list is a dict with at least two names: ``address_type``
   (a string whose value is either "IPv4" or
   "IPv6") and ``address_data`` (whose value is a string representation of 
   an IP address). Note
   that the ``dnssec_return_only_secure`` extension affects what
   will appear in the just_address_answers list. Also note if
   later versions of the DNS return other address types, those
   types will appear in this list as well.

  .. py:attribute:: replies_full

   The ``replies_full`` attribute is a Python dictionary
   containing the entire set of records returned by the
   query.  

   The following lists the status codes for response
   objects. Note that, if the status is that there are no
   responses for the query, the lists in ``replies_full`` and
   ``replies_tree`` will have zero length.

   The top level of ``replies_tree`` can optionally have the
   following names: ``canonical_name``,
   ``intermediate_aliases`` (a list), ``answer_ipv4_address``
   ``answer_ipv6_address``, and ``answer_type``
   (an integer constant.).

   * The value of ``canonical_name`` is the name that the API used for its lookup. It is in FQDN presentation format.
   * The values in the ``intermediate_aliases`` list are domain
     names from any CNAME or unsynthesized DNAME found when
     resolving the original query. The list might have zero
     entries if there were no CNAMEs in the path. These may
     be useful, for example, for name comparisons when
     following the rules in RFC 6125.
   * The value of ``answer_ipv4_address`` and
     ``answer_ipv6_address`` are the addresses of the server
     from which the answer was received.
   * The value of ``answer_type`` is the type of name service that generated the response. The values are:

   If the call was :meth:`address`, the
   top level of ``replies_tree`` has an additional name,
   ``just_address_answers`` (a list). The value of
   ``just_address_answers`` is a list that contains all of the A
   and AAAA records from the ``answer`` sections of any of the
   replies, in the order they appear in the replies. Each item
   in the list is a dict with at least two names: ``address_type``
   (a string whose value is either "IPv4" or
   "IPv6") and ``address_data`` (whose value is a string representation of 
   an IP address). Note
   that the ``dnssec_return_only_secure`` extension affects what
   will appear in the just_address_answers list. Also note if
   later versions of the DNS return other address types, those
   types will appear in this list as well.

   The API can make service discovery through SRV records
   easier. If the call was :meth:`service`, the top level of ``replies_tree has`` an
   additional name, ``srv_addresses`` (a list). The list is ordered
   by priority and weight based on the weighting algorithm in
   :rfc:`2782`, lowest priority value first. Each element of the
   list is a dictionary that has at least two names: ``port`` and
   ``domain_name``. If the API was able to determine the address of
   the target domain name (such as from its cache or from the
   Additional section of responses), the dict for an element
   will also contain ``address_type`` (whose value 
   is currently either "IPv4" or "IPv6") and ``address_data``
   (whose value is a string representation of an IP address). Note that the
   ``dnssec_return_only_secure`` extension affects what will appear
   in the ``srv_addresses`` list.

  .. py:attribute:: validation_chain

   The ``validation_chain`` attribute is a Python list
   containing the set of DNSSEC-related records needed for
   validation of a particular response.   This set comes as
   validation_chain (a list) at the top level of the
   response object. This list includes all resource record
   dicts for all the resource records (DS, DNSKEY and their
   RRSIGs) that are needed to perform the validation from
   the root up.                    

  .. py:attribute:: call_reporting

   A list of dictionaries containing call_debugging
   information, if requested in the query.

  .. py:attribute:: replies_tree

   The names in each entry in the the ``replies_tree`` list for DNS
   responses include ``header`` (a dict), ``question`` (a dict), ``answer``
   (a list), ``authority`` (a list), and ``additional`` (a list),
   corresponding to the sections in the DNS message format. The
   ``answer``, ``authority``, and ``additional`` lists each contain zero or
   more dicts, with each dict in each list representing a
   resource record.

   The names in the ``header`` dict are all the fields from 
   :rfc:`1035#section-4.1.1`.
   They are: ``id``, ``qr``, ``opcode``, ``aa``, ``tc``, ``rd``,
   ``ra``, ``z``, ``rcode``, ``qdcount``, ``ancount``, ``nscount``, and ``arcount``. All
   are integers.

   The names in the ``question`` dict are the three fields from
   :rfc:`1035#section-4.1.2`: ``qname``, ``qtype``, and ``qclass``.

   Resource records are a bit different than headers and
   question sections in that the RDATA portion often has its
   own structure. The other names in the resource record dictionaries
   are ``name``, ``type``, ``class``, ``ttl``,
   and ``rdata`` (which is a dict); there is no name equivalent to the
   RDLENGTH field. The OPT resource record does not have the
   ``class`` and the ``ttl`` name, but instead provides
   ``udp_payload_size``, ``extended_rcode``, ``version``,
   ``do``, and ``z``.

   The ``rdata`` dictionary has different names for each response
   type. There is a complete list of the types defined in the
   API. For names that end in "-obsolete" or "-unknown", the
   data are the entire RDATA field. For example, the ``rdata``
   for an A record has a name ``ipv4_address``; the
   rdata for an SRV record has the names ``priority``,
   ``weight``, ``port``, and ``target``.

   Each rdata dict also has a ``rdata_raw`` element. This
   is useful for types not defined in this version of the
   API. It also might be of value if a later version of the API
   allows for additional parsers. Thus, doing a query for types
   not known by the API still will return a result: an ``rdata``
   with just a ``rdata_raw``.

   It is expected that later extensions to the API will give
   some DNS types different names. It is also possible that
   later extensions will change the names for some of the DNS
   types listed above.

   For example, a response to a Context.address() call for
   www.example.com would look something like this:

::

 {     # This is the response object
  "replies_full": [ <bindata of the first response>, <bindata of the second response> ],
  "just_address_answers":
  [
    {
      "address_type": <bindata of "IPv4">,
      "address_data": <bindata of 0x0a0b0c01>,
    },
    {
      "address_type": <bindata of "IPv6">,
      "address_data": <bindata of 0x33445566334455663344556633445566>
    }
  ],
  "canonical_name": <bindata of "www.example.com">,
  "answer_type": NAMETYPE_DNS,
  "intermediate_aliases": [],
  "replies_tree":
  [
    {     # This is the first reply
      "header": { "id": 23456, "qr": 1, "opcode": 0, ... },
      "question": { "qname": <bindata of "www.example.com">, "qtype": 1, "qclass": 1 },
      "answer":
      [
        {
          "name": <bindata of "www.example.com">,
          "type": 1,
          "class": 1,
          "ttl": 33000,
          "rdata":
          {
            "ipv4_address": <bindata of 0x0a0b0c01>
            "rdata_raw": <bindata of 0x0a0b0c01>
          }
        }
      ],
      "authority":
      [
        {
          "name": <bindata of "ns1.example.com">,
          "type": 1,
          "class": 1,
          "ttl": 600,
          "rdata":
          {
            "ipv4_address": <bindata of 0x65439876>
            "rdata_raw": <bindata of 0x65439876>
          }
        }
      ]
      "additional": [],
      "canonical_name": <bindata of "www.example.com">,
      "answer_type": NAMETYPE_DNS
    },
    {     # This is the second reply
      "header": { "id": 47809, "qr": 1, "opcode": 0, ... },
      "question": { "qname": <bindata of "www.example.com">, "qtype": 28, "qclass": 1 },
      "answer":
      [
        {
          "name": <bindata of "www.example.com">,
          "type": 28,
          "class": 1,
          "ttl": 1000,
          "rdata":
          {
            "ipv6_address": <bindata of 0x33445566334455663344556633445566>
            "rdata_raw": <bindata of 0x33445566334455663344556633445566>
          }
       }
      ],
      "authority": [  # Same as for other record... ]
      "additional": [],
    },
  ]
 }




Return Codes
------------
The return codes for all the functions are:

.. py:data:: RETURN_GOOD

  Good

.. py:data:: RETURN_GENERIC_ERROR

  Generic error

.. py:data:: RETURN_BAD_DOMAIN_NAME

  Badly-formed domain name in first argument

.. py:data:: RETURN_BAD_CONTEXT

  The context has internal deficiencies

.. py:data:: RETURN_CONTEXT_UPDATE_FAIL

  Did not update the context

.. py:data:: RETURN_UNKNOWN_TRANSACTION

  An attempt was made to cancel a callback with a transaction_id that is not recognized

.. py:data:: RETURN_NO_SUCH_LIST_ITEM

  A helper function for lists had an index argument that was too high.

.. py:data:: RETURN_NO_SUCH_DICT_NAME

  A helper function for dicts had a name argument that for a name that is not in the dict.

.. py:data:: RETURN_WRONG_TYPE_REQUESTED

  A helper function was supposed to return a certain type for an item, but the wrong type was given.

.. py:data:: RETURN_NO_SUCH_EXTENSION

  A name in the extensions dict is not a valid extension.

.. py:data:: RETURN_EXTENSION_MISFORMAT

  One or more of the extensions have a bad format.

.. py:data:: RETURN_DNSSEC_WITH_STUB_DISALLOWED

  A query was made with a context that is using stub resolution and a DNSSEC extension specified.

.. py:data:: RETURN_MEMORY_ERROR

  Unable to allocate the memory required.

.. py:data:: RETURN_INVALID_PARAMETER

  A required parameter had an invalid value.

.. py:data:: RETURN_NOT_IMPLEMENTED

  The requested API feature is not implemented.
