/**
 *
 * \ file pygetdns_util.c
 * @brief utility functions to support pygetdns bindings
 */


/*
 * Copyright (c) 2014, Verisign, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the <organization> nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Include. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include <ldns/ldns.h>
#include "pygetdns.h"

/* rtypes supported in replies_tree
A (1)  done

ipv4_address (a bindata)

NS (2) done

nsdname (a bindata)

MD (3) done

madname (a bindata)

MF (4) done

madname (a bindata)

CNAME (5) done

cname (a bindata)

SOA (6) done

mname (a bindata), rname (a bindata), serial (an int), refresh (an int), refresh (an int), retry (an int), and expire (an int)

MB (7) done

madname (a bindata)

MG (8)

mgmname (a bindata)

MR (9)

newname (a bindata)

NULL (10)

anything (a bindata)

WKS (11) done

address (a bindata), protocol (an int), and bitmap (a bindata)

PTR (12) done

ptrdname (a bindata)

HINFO (13) done

cpu (a bindata) and os (a bindata)

MINFO (14) done

rmailbx (a bindata) and emailbx (a bindata)

MX (15) done, not working as expected.

preference (an int) and exchange (a bindata)

TXT (16) done

txt_strings (a list) which contains zero or more bindata elements that are text strings

RP (17) done

mbox_dname (a bindata) and txt_dname (a bindata)

AFSDB (18) done

subtype (an int) and hostname (a bindata)

done (19) done

psdn_address (a bindata)

ISDN (20) done

isdn_address (a bindata) and sa (a bindata)

RT (21) done

preference (an int) and intermediate_host (a bindata)

NSAP (22) done

nsap (a bindata)

SIG (24) done

sig_obsolete (a bindata)

KEY (25) done

key_obsolete (a bindata)

PX (26)

preference (an int), map822 (a bindata), and mapx400 (a bindata)

GPOS (27)

longitude (a bindata), latitude (a bindata), and altitude (a bindata)

AAAA (28) done

ipv6_address (a bindata)

LOC (29) done

loc_obsolete (a bindata)

NXT (30) done

nxt_obsolete (a bindata)

EID (31) done

eid_unknown (a bindata)

NIMLOC (32) done

nimloc_unknown (a bindata)

SRV (33)

priority (an int), weight (an int), port (an int), and target (a bindata)

ATMA (34)

format (an int) and address (a bindata)

NAPTR (35)

order (an int), preference (an int), flags (a bindata), service (a bindata), regexp (a bindata), and replacement (a bindata).

KX (36)

preference (an int) and exchanger (a bindata)

CERT (37) done

type (an int), key_tag (an int), algorithm (an int), and certificate_or_crl (a bindata)

A6 (38) done

a6_obsolete (a bindata)

DNAME (39) done

target (a bindata)

SINK (40) done

sink_unknown (a bindata)

OPT (41)  done

options (a list). Each element of the options list is a dict with two names: option_code (an int) and option_data (a bindata).

APL (42) done

apitems (a list). Each element of the apitems list is a dict with four names: address_family (an int), prefix (an int), n (an int), and afdpart (a bindata)

DS (43) DONE

key_tag (an int), algorithm (an int), digest_type (an int), and digest (a bindata)

SSHFP (44)

algorithm (an int), fp_type (an int), and fingerprint (a bindata)

IPSECKEY (45)

algorithm (an int), gateway_type (an int), precedence (an int), gateway, and public_key (a bindata)

RRSIG (46)

type_covered (an int), algorithm (an int), labels (an int), original_ttl (an int), signature_expiration (an int), signature_inception (an int), key_tag (an int), signers_name (a bindata), and signature (a bindata)

NSEC (47)

next_domain_name (a bindata) and type_bit_maps (a bindata)

DNSKEY (48)

flags (an int), protocol (an int), algorithm (an int), and public_key (a bindata)

DHCID (49) done

dhcid_opaque (a bindata)

NSEC3 (50)

hash_algorithm (an int), flags (an int), iterations (an int), salt (a bindata), next_hashed_owner_name (a bindata), and type_bit_maps (a bindata)

NSEC3PARAM (51)

hash_algorithm (an int), flags (an int), iterations (an int), and salt (a bindata)

TLSA (52)

certificate_usage (an int), selector (an int), matching_type (an int), and certificate_association_data (a bindata).

HIP (55)

pk_algorithm (an int), hit (a bindata), public_key (a bindata), and rendezvous_servers (a list) with each element a bindata with the dname of the rendezvous_server.

NINFO (56) done

ninfo_unknown (a bindata)

RKEY (57) done

rkey_unknown (a bindata)

TALINK (58) done

talink_unknown (a bindata)

CDS (59) done

cds_unknown (a bindata)

SPF (99) done

text (a bindata)

UINFO (100) done

uinfo_unknown (a bindata)

UID (101) done

uid_unknown (a bindata)

GID (102) done

gid_unknown (a bindata)

UNSPEC (103) done

unspec_unknown (a bindata)

NID (104)

preference (an int) and node_id (a bindata)

L32 (105)

preference (an int) and locator32 (a bindata)

L64 (106)

preference (an int) and locator64 (a bindata)

LP (107)

preference (an int) and fqdn (a bindata)

EUI48 (108)

eui48_address (a bindata)

EUI64 (109)

eui64_address (a bindata)

TKEY (249)

algorithm (a bindata), inception (an int), expiration (an int), mode (an int), error (an int), key_data (a bindata), and other_data (a bindata)

TSIG (250)

algorithm (a bindata), time_signed (a bindata), fudge (an int), mac (a bindata), original_id (an int), error (an int), and other_data (a bindata)

MAILB (253) done

mailb-unknown (a bindata)

MAILA (254) done

maila-unknown (a bindata)

URI (256)

priority (an int), weight (an int), and target (a bindata)

CAA (257)

flags (an int), tag (a bindata), and value (a bindata)

TA (32768) done

ta_unknown (a bindata)

DLV (32769)

Identical to DS (43)
 */

struct getdns_dict *
extensions_to_getdnsdict(PyDictObject *pydict)
{
    struct getdns_dict *newdict = 0;
    Py_ssize_t pos = 0, optiondictpos = 0, optionlistpos = 0;
    PyObject *key, *value;
    char *tmpoptionlistkey;
    struct getdns_list *optionslist = 0;         /* for options list */
    int optionlistsize;                   /* how many options in options list */
    int i;                                /* loop counter */
    PyObject *optionitem;
    PyObject *optiondictkey, *optiondictvalue; /* for processing option list dicts */
    struct getdns_bindata *option_data;
    struct getdns_dict *tmpoptions_list_dict; /* a dict to hold add_opt_parameters[options] stuff */

    if (!PyDict_Check(pydict))  {
        PyErr_SetString(getdns_error, "Expected dict, didn't get one");
        return NULL;
    }
    newdict = getdns_dict_create(); /* this is what we'll return */

    while (PyDict_Next((PyObject *)pydict, &pos, &key, &value))  { /* these options take TRUE or FALSE args */
        char *tmp_key;
        int  tmp_int;

        tmp_key = PyString_AsString(PyObject_Str(key));
        if ( (!strncmp(tmp_key, "dnssec_return_status", strlen("dnssec_return_status")))  ||
             (!strncmp(tmp_key, "return_only_secure", strlen("return_only_secure")))  ||
             (!strncmp(tmp_key, "return_both_v4_and_v6", strlen("return_both_v4_and_v6")))  ||
             (!strncmp(tmp_key, "dnssec_return_supporting_responses", strlen("dnssec_return_supporting_responses")))  ||
             (!strncmp(tmp_key, "return_api_information", strlen("return_api_information")))  ||
             (!strncmp(tmp_key, "return_call_debugging", strlen("return_call_debugging")))  ||
             (!strncmp(tmp_key, "add_warning_for_bad_dns", strlen("add_warning_for_bad_dns"))) )  {
            if (!PyInt_Check(value))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                return NULL;
            }
            if ( !((PyInt_AsLong(value) == GETDNS_EXTENSION_TRUE) || (PyInt_AsLong(value) == GETDNS_EXTENSION_FALSE)) )  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                return NULL;
            }
            tmp_int = (int)PyInt_AsLong(value);
            (void)getdns_dict_set_int(newdict, tmp_key, tmp_int);
        } else if (!strncmp(tmp_key, "specify_class", strlen("specify_class")))  { /* takes integer */
            if (!PyInt_Check(value))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                return NULL;
            }
            tmp_int = (int)PyInt_AsLong(value);
            (void)getdns_dict_set_int(newdict, tmp_key, tmp_int);

/*
 *  dns OPT resource record setup
 *
 *    extensions['add_opt_parameters'][option_name]
 */


        } else if (!strncmp(tmp_key, "add_opt_parameters", strlen("add_opt_parameters")))  { /* this is a dict */
            PyObject *in_optdict; /* points at dictionary passed in */
            struct getdns_dict *out_optdict = 0;
            Py_ssize_t opt_pos = 0;
            PyObject *opt_key, *opt_value;
            char *tmp_opt_key;
            int optint;

            in_optdict = value;
            if (!PyDict_Check(in_optdict))  {
                PyErr_SetString(getdns_error, "Expected dict, didn't get one");
                return NULL;
            }
            out_optdict = getdns_dict_create();
            while (PyDict_Next((PyObject *)in_optdict, &opt_pos, &opt_key, &opt_value))  {
                tmp_opt_key = PyString_AsString(opt_key);
                if ( (!strncmp(tmp_opt_key, "maximum_udp_payload_size", strlen("maximum_udp_payload_size")))  ||
                     (!strncmp(tmp_opt_key, "extended_rcode", strlen("extended_rcode"))) ||
                     (!strncmp(tmp_opt_key, "version", strlen("version"))) ||
                     (!strncmp(tmp_opt_key, "do_bit", strlen("do_bit"))) )  {
                    if (!PyInt_Check(opt_value))  {
                        PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                        return NULL;
                    }
                    optint = (int)PyInt_AsLong(opt_value);
                    (void)getdns_dict_set_int(out_optdict, tmp_opt_key, optint);
                }  else if (!strncmp(tmp_opt_key, "options", strlen("options")))  { /* options */
/*
 * options with arbitrary opt code
 *
 *    add_opt_parameters is a dict containing
 *      options is a list containing
 *        dicts for each option containing
 *          option_code (int)
 *          option_data (bindata)
 *    
 */

                    if (!PyList_Check(opt_value))  {
                        PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                        return NULL;
                    }
                    optionslist = getdns_list_create();

                    optionlistsize = PyList_Size(opt_value);

                    for ( i = 0 ; i < optionlistsize ; i++)  {
                        tmpoptions_list_dict = getdns_dict_create();
                        optionitem = PyList_GetItem(opt_value, i);
                        if (!PyDict_Check(optionitem))  {
                            PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                            return NULL;
                        }
                        /* optionitem should be a dict with keys option_code and option_data */
                        while (PyDict_Next(optionitem, &optiondictpos, &optiondictkey, &optiondictvalue))  {
                            tmpoptionlistkey = PyString_AsString(PyObject_Str(optiondictkey));
                            if  (!strncmp(tmpoptionlistkey, "option_code", strlen("option_code")))  {
                                if (!PyInt_Check(optiondictvalue))  {
                                    PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                                    return NULL;
                                }
                                getdns_dict_set_int(tmpoptions_list_dict, "option_code", (uint32_t)PyInt_AsLong(optiondictvalue));
                            }  else if (!strncmp(tmpoptionlistkey, "option_data", strlen("option_data")))  {
                                option_data = (struct getdns_bindata *)malloc(sizeof(struct getdns_bindata));
                                option_data->size = PyObject_Length(optiondictvalue);
                                option_data->data = (uint8_t *)PyString_AsString(PyObject_Bytes(optiondictvalue)); /* This is almost certainly wrong */
                                getdns_dict_set_bindata(tmpoptions_list_dict, "option_data", option_data);
                            } else  {
                                PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                                return NULL;
                            }
                            getdns_list_set_dict(optionslist, optionlistpos, tmpoptions_list_dict);
                        }
                    } /* for i ... optionlistsize */
                    getdns_dict_set_list(out_optdict, "options", optionslist);
                }     /* for options */
                getdns_dict_set_dict(newdict, "add_opt_parameters", out_optdict);
            } /* while PyDict_Next(tmp_optdict ... ) */
        } else {
            PyErr_SetString(getdns_error, GETDNS_RETURN_NO_SUCH_EXTENSION_TEXT);
            return NULL;
        }
    }
    return newdict;
}

PyObject *
decode_getdns_response(struct getdns_dict *response)
{
    uint32_t error;
    char error_str[512];
    struct getdns_list *addr_list;
    size_t n_addrs;
    getdns_return_t ret;
    size_t i;
    struct getdns_dict *addr_dict;
    struct getdns_bindata *addr;
    char *addr_str;
    PyObject *results;

    (void)getdns_dict_get_int(response, "status", &error);
    if (error != GETDNS_RESPSTATUS_GOOD)  {
        sprintf(error_str, "No answers, return value %d", error);
        PyErr_SetString(getdns_error, error_str);
        return NULL;
    }
    if ((ret = getdns_dict_get_list(response, "just_address_answers",
                                    &addr_list)) != GETDNS_RETURN_GOOD)  {
        sprintf(error_str, "Extracting answers failed: %d", ret);
        PyErr_SetString(getdns_error, error_str);
        return NULL;
    }
    if ((results = PyList_New(0)) == NULL)  {
        PyErr_SetString(getdns_error, "Unable to allocate response list");
        return NULL;
    }
    (void)getdns_list_get_length(addr_list, &n_addrs);
    for ( i = 0 ; i < n_addrs ; i++ )  {
        (void)getdns_list_get_dict(addr_list, i, &addr_dict);
        (void)getdns_dict_get_bindata(addr_dict, "address_data", &addr);
        addr_str = getdns_display_ip_address(addr);
        PyList_Append(results, PyString_FromString(addr_str));
    }
    return results;
}


/*
 * Error checking helper
 */
void error_exit(char* msg, getdns_return_t ret)
{
    char error_str[512];
    if (ret != GETDNS_RETURN_GOOD)  {
        sprintf(error_str, "%s: %d", msg, ret);
        printf("ERROR: %s: %d", msg, ret);
        PyErr_SetString(getdns_error, error_str);
    }
}

/*
 * Helper function for constructing a tree of PyDicts for the response.
 */
PyObject *
decode_getdns_replies_tree_response(struct getdns_dict *response)
{
    uint32_t error;
    struct getdns_list *addr_list;
    size_t n_addrs;
    getdns_return_t ret;
    PyObject *results;
    PyObject *resultslist;
    size_t rec_count = 0;
    getdns_return_t this_ret;

    printf("decode_getdns_replies_tree_response\n");
    (void)getdns_dict_get_int(response, "status", &error);
    if (error != GETDNS_RESPSTATUS_GOOD)  {
    	error_exit("No answers, return value", error);
        return NULL;
    }

    if ((ret = getdns_dict_get_list(response, "replies_tree",
                                    &addr_list)) != GETDNS_RETURN_GOOD)  {
    	error_exit("Extracting answers failed", ret);
        return NULL;
    }

    results = PyDict_New();
    if ((resultslist = PyList_New(0)) == NULL)  {
       error_exit("Unable to allocate response list", 0);
        return NULL;
    }

    (void)getdns_list_get_length(addr_list, &n_addrs);

    printf("Num of addrs = %lu\n", n_addrs);
    for ( rec_count = 0; rec_count < n_addrs; ++rec_count )
    {

	    struct getdns_dict *this_record;
	    //TODO: Handle errors for below 2 functions
        this_ret = getdns_list_get_dict(
        		addr_list, rec_count, &this_record);

        // Get the header section
        printf("Getting header...\n");
        if (!build_response_header(response, resultslist,
        		this_record)) {
        	return NULL;
        }

        // Get the question section
        printf("Getting question...\n");
        if (!build_response_question(response, resultslist,
        		this_record)) {
        	return NULL;
        }
        /*
        // Get the answer_type section
        printf("Getting answer_type...\n");
        if (!build_response_answer_type("answer_type", response, resultslist,
        		this_record, rec_count)) {
        	return NULL;
        }

        // Get the answer_type section
        printf("Getting canonical_name...\n");
        if (!build_response_canonical_name("canonical_name", response, resultslist,
        		this_record, rec_count)) {
        	return NULL;
        }
        */

        // Get the answer section
        printf("Getting answer...\n");
        if (!build_response_components("answer", response, resultslist,
        		this_record, rec_count)) {
        	return NULL;
        }
        // Get the authority section
        printf("Getting authority...\n");
        if (!build_response_components("authority", response, resultslist,
        		this_record, rec_count)) {
        	return NULL;
        }
        // Get the additional section
        printf("Getting additional...\n");
        if (!build_response_components("additional", response, resultslist,
        		this_record, rec_count)) {
        	return NULL;
        }

    }
    PyDict_SetItem(results, PyString_FromString("replies_tree"), resultslist);
    return results;
}

/*
 * Helper function to process each answer type
 * Handle lists in process_list_data
 */
int process_data(size_t rec_count,
		         size_t rr_count,
		         uint32_t type,
		         struct getdns_bindata* name,
		         uint32_t class,
		         uint32_t ttl,
		         char* rrtype,
		         PyObject* resultslist,
		         struct getdns_list *this_answer,
		         struct getdns_dict *response,
		         char* component)
{
    getdns_return_t this_ret;
    struct getdns_dict *this_rr = NULL;
    struct getdns_dict *this_rdata = NULL;
	struct getdns_bindata *this_a_record = NULL;
	uint32_t intdata;
	struct getdns_list *listdata = NULL;

	printf("process_data rrtype: %s type %u class %u ttl %u\n",
			rrtype, type, class, ttl);
    PyObject *resultitem = PyDict_New();

    this_ret = getdns_list_get_dict(
    		this_answer, rr_count, &this_rr);

    // Get the RDATA
    this_ret = getdns_dict_get_dict(
    		this_rr, "rdata", &this_rdata);

    //TODO: How do I know which datatype I got back?
    // eg int or bindata etc?
	this_ret = getdns_dict_get_bindata(
			this_rdata, rrtype, &this_a_record);
	if (this_ret == GETDNS_RETURN_WRONG_TYPE_REQUESTED)
	{
		this_ret = getdns_dict_get_int(
				this_rdata, rrtype, &intdata);
		if (this_ret == GETDNS_RETURN_WRONG_TYPE_REQUESTED)
		{
			this_ret = getdns_dict_get_list(
					this_rdata, rrtype, &listdata);
			if (this_ret == GETDNS_RETURN_WRONG_TYPE_REQUESTED)
			{
				this_ret = getdns_dict_get_names(
						this_rdata, &listdata);
				{
				fprintf(stderr,
					"Weird: the A record at %d in record at %d "
					"had no data. Exiting with error %d.\n",
					(int) rr_count, (int) rec_count, this_ret);
				getdns_dict_destroy(response);
				return 0;
				}
			}
		}
	}
	char *this_address_str = getdns_display_ip_address(this_a_record);
	if (this_address_str) {
		printf("The %s address is %s count %d\n", rrtype, this_address_str, rr_count);

		// add items to answer
        PyObject *resultitem = PyDict_New();
        PyObject *rdata = PyDict_New();
        PyDict_SetItem(rdata, PyString_FromString(rrtype),
        		       PyString_FromString(this_address_str));

		PyObject *res1 = Py_BuildValue("{s:i,s:i,s:i,s:s,s:O}",
				"type", type, "class", class, "ttl", ttl, "name",
				(char *)name->data, "rdata", rdata);

		PyDict_SetItem(resultitem, PyString_FromString(component), res1);
		PyList_Append(resultslist, resultitem);
		free(this_address_str);
	} else {
		// Build answer without address, eg for SOA.
		PyObject *res1;
		printf("Building the %s\n", rrtype);
		// eg. for SOA (6)
		// mname (a bindata), rname (a bindata), serial (an int), refresh (an int),
		// refresh (an int), retry (an int), and expire (an int)
		// We add a record for each field returned, eg. name = 'mname'
		// and rdata = 'www.panix.com' and so on for other fields.
		if (this_a_record) {
			printf("Building the %s.\n", rrtype);

			res1 = Py_BuildValue("{s:i,s:i,s:i,s:s,s:s}",
					"type", type, "class", class, "ttl", ttl, "name",
					rrtype,"rdata",(char *)this_a_record->data);
			printf("Built the %s and value = %s.\n", rrtype,
					(char *)this_a_record->data);
		} else {
			res1 = Py_BuildValue("{s:i,s:i,s:i,s:s,s:i}",
					"type", type, "class", class, "ttl", ttl, "name",
					rrtype,"rdata",intdata);
			printf("Built the %s and value = %u.\n", rrtype,
					intdata);

		}

		PyDict_SetItem(resultitem, PyString_FromString(component), res1);
		PyList_Append(resultslist, resultitem);
	}
	return 1;
}

/*
 * Helper function to process each answer type
 * Handle lists in process_list_data where a list element is a bindata
 * eg TXT rtype
 */
int process_list_bindata(size_t rec_count,
		         size_t rr_count,
		         uint32_t type,
		         struct getdns_bindata* name,
		         uint32_t class,
		         uint32_t ttl,
		         char* rrtype,
		         PyObject* resultslist,
		         struct getdns_list *this_answer,
		         struct getdns_dict *response,
		         char* component)
{
    getdns_return_t this_ret;
    struct getdns_dict *this_rr = NULL;
    struct getdns_dict *this_rdata = NULL;
	struct getdns_list *listdata = NULL;

	printf("process_data rrtype: %s type %u class %u ttl %u\n",
			rrtype, type, class, ttl);
    PyObject *resultitem = PyDict_New();

    this_ret = getdns_list_get_dict(
    		this_answer, rr_count, &this_rr);

    // Get the RDATA
    this_ret = getdns_dict_get_dict(
		this_rr, "rdata", &this_rdata);

	this_ret = getdns_dict_get_list(
			this_rdata, rrtype, &listdata);
	if (this_ret == GETDNS_RETURN_WRONG_TYPE_REQUESTED)
	{
		fprintf(stderr,
			"Weird: the A record at %d in record at %d "
			"had no data. Exiting with error %d.\n",
			(int) rr_count, (int) rec_count, this_ret);
		getdns_dict_destroy(response);
		return 0;
	}

	// build list values and add to response
    size_t num_vals;
    // Ignore any error
    this_ret = getdns_list_get_length(listdata, &num_vals);
    printf("Error: %d. num %d\n", this_ret, num_vals);
    if (this_ret == GETDNS_RETURN_GOOD)
    {
		// Go through each record
		size_t i = 0;
		for ( i = 0; i < num_vals; ++i )
		{
			// get value
			struct getdns_bindata *this_data;
			this_ret = getdns_list_get_bindata(listdata, i, &this_data);
			printf("Error: %d.\n", this_ret);
			if (this_ret == GETDNS_RETURN_GOOD && this_data) {
				printf("Building the %s.\n", rrtype);
				PyObject *res1;
				res1 = Py_BuildValue("{s:i,s:i,s:i,s:s,s:s}",
						"type", type, "class", class, "ttl", ttl, "name",
						rrtype,"rdata",(char *)this_data->data);
				printf("Built the %s and value = %s.\n", rrtype,
						(char *)this_data->data);

				PyDict_SetItem(resultitem, PyString_FromString(component), res1);
				PyList_Append(resultslist, resultitem);
			}
		}
    }
	return 1;
}

/*
 * Helper function to process each answer type
 * Handle lists in process_list_data where a list element is a dict
 * eg OPT rtype
 */
int process_list_dict(size_t rec_count,
		         size_t rr_count,
		         uint32_t type,
		         struct getdns_bindata* name,
		         uint32_t class,
		         uint32_t ttl,
		         char* rrtype,
		         PyObject* resultslist,
		         struct getdns_list *this_answer,
		         struct getdns_dict *response,
		         char* component)
{
    getdns_return_t this_ret;
    struct getdns_dict *this_rr = NULL;
    struct getdns_dict *this_rdata = NULL;
	struct getdns_list *listdata = NULL;

	printf("process_data rrtype: %s type %u class %u ttl %u\n",
			rrtype, type, class, ttl);
    PyObject *resultitem = PyDict_New();

    this_ret = getdns_list_get_dict(
    		this_answer, rr_count, &this_rr);
    printf("Error: %d.\n", this_ret);
    // Get the RDATA
    this_ret = getdns_dict_get_dict(
		this_rr, "rdata", &this_rdata);

    printf("Error: %d.\n", this_ret);

	this_ret = getdns_dict_get_list(
			this_rdata, rrtype, &listdata);
	if (this_ret == GETDNS_RETURN_WRONG_TYPE_REQUESTED)
	{
		fprintf(stderr,
			"Weird: the A record at %d in record at %d "
			"had no data. Exiting with error %d.\n",
			(int) rr_count, (int) rec_count, this_ret);
		getdns_dict_destroy(response);
		return 0;
	}

	// build list values and add to response
    size_t num_vals;
    this_ret = getdns_list_get_length(listdata, &num_vals);
    printf("Error: %d. The num of recs is %d\n", this_ret, num_vals);
    // Go through each record
    size_t i = 0;
    for ( i = 0; i < num_vals; ++i )
    {
    	struct getdns_dict *this_val;
        this_ret = getdns_list_get_dict(listdata, i, &this_val);  // Ignore any error
        // get value
        struct getdns_bindata *this_data;
        this_ret = getdns_dict_get_bindata(this_val, rrtype, &this_data); // Ignore any error
        char *this_str = getdns_display_ip_address(this_data);
        printf("The data is %s\n", this_str);

		printf("Building the %s.\n", rrtype);
		PyObject *res1;
		res1 = Py_BuildValue("{s:i,s:i,s:i,s:s,s:s}",
				"type", type, "class", class, "ttl", ttl, "name",
				rrtype,"rdata",(char *)this_str);
		printf("Built the %s and value = %s.\n", rrtype,
				(char *)this_str);
        free(this_str);

		PyDict_SetItem(resultitem, PyString_FromString(component), res1);
		PyList_Append(resultslist, resultitem);
	}
	return 1;
}

/*
 * Pass in "answer", "authority" or "additional" to build the relavant sections
 */
int build_response_components(char* component,
		                      struct getdns_dict *response,
		                      PyObject *resultslist,
		                      struct getdns_dict *this_record,
		                      size_t rec_count)
{
    getdns_return_t this_ret;
    size_t rr_count;

    struct getdns_list *this_component;
    this_ret = getdns_dict_get_list(
    		this_record, component, &this_component);

    /* Get each RR in the answer section */
    size_t num_rrs;
    this_ret = getdns_list_get_length(this_component, &num_rrs);
    printf("Num of rrs for %s = %lu\n", component, num_rrs);

    for (rr_count = 0; rr_count < num_rrs; ++rr_count )
    {
        //PyObject *resultitem = PyDict_New();
        struct getdns_dict *this_rr = NULL;

        this_ret = getdns_list_get_dict(
        		this_component, rr_count, &this_rr);
        if (this_ret != GETDNS_RETURN_GOOD)  {
            error_exit("getdns_list_get_dict failed", this_ret);
            return 0;
        }
        // Get the RDATA
        struct getdns_dict * this_rdata = NULL;
        this_ret = getdns_dict_get_dict(
        		this_rr, "rdata", &this_rdata);
        if (this_ret != GETDNS_RETURN_GOOD)  {
        	error_exit("getdns_get_get_dict rdata failed", this_ret);
            return 0;
        }

        //get the name
        struct getdns_bindata *name = NULL;
    	this_ret = getdns_dict_get_bindata(
    			this_rr, "name", &name);
    	if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME)
    	{
    		fprintf(stderr,
    			"Weird: the A record at %d in record at %d "
    			"had no address. Exiting.\n",
    			(int) rr_count, (int) rec_count);
    		getdns_dict_destroy(response);
    		return 0;
    	}

        // Get the  type
        uint32_t this_type;
        this_ret = getdns_dict_get_int(
        		this_rr, "type", &this_type);
        if (this_ret != GETDNS_RETURN_GOOD)  {
        	error_exit("getdns_dict_get_int failed", this_ret);
            return NULL;
        }

        // Get the class
        uint32_t class;
        this_ret = getdns_dict_get_int(
        		this_rr, "class", &class);
        if (this_ret != GETDNS_RETURN_GOOD)  {
        	error_exit("getdns_dict_get_int failed", this_ret);
            return NULL;
        }

        // Get the ttl
        uint32_t ttl;
        this_ret = getdns_dict_get_int(
        		this_rr, "ttl", &ttl);
        if (this_ret != GETDNS_RETURN_GOOD)  {
        	error_exit("getdns_dict_get_int failed", this_ret);
            return NULL;
        }

    	printf("type %u class %u ttl %u\n", this_type, class, ttl);

        /* If it is a valid RR stash the value in PyObject */
        switch (this_type) {

        case GETDNS_RRTYPE_A:
        {
        	if (!process_data(rec_count, rr_count,
        			          this_type, name, class, ttl,
        			          "ipv4_address", resultslist,
        			          this_component, response, component)) {
        		return 0;
        	}
        	break;
        }
        case GETDNS_RRTYPE_AAAA:
       {
			if (!process_data(rec_count, rr_count,
					          this_type, name, class, ttl,
					          "ipv6_address", resultslist,
					          this_component, response, component)) {
				return 0;
			}
			break;
        }
        case GETDNS_RRTYPE_NS:
       {
			if (!process_data(rec_count, rr_count,
					          this_type, name, class, ttl,
					          "nsdname", resultslist,
					          this_component, response, component)) {
				return 0;
			}
			break;
        }
        case GETDNS_RRTYPE_MX:
       {
    	   //TODO: not working as expected for gmail.com
			if (!process_data(rec_count, rr_count,
					          this_type, name, class, ttl,
					          "preference", resultslist,
					          this_component, response, component)) {
				return 0;
			}
			break;
			if (!process_data(rec_count, rr_count,
					          this_type, name, class, ttl,
					          "exchange", resultslist,
					          this_component, response, component)) {
				return 0;
			}
			break;
        }
        case GETDNS_RRTYPE_MD:
        case GETDNS_RRTYPE_MF:
        case GETDNS_RRTYPE_MB:
       {
			if (!process_data(rec_count, rr_count,
					          this_type, name, class, ttl,
					          "madname", resultslist,
					          this_component, response, component)) {
				return 0;
			}
			break;
        }
        case GETDNS_RRTYPE_CNAME:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "cname", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			break;
         }
        case GETDNS_RRTYPE_CERT:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "type", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "key_tag", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "algorithm", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "certificate_or_crl", resultslist,
							  this_component, response, component)) {
				return 0;
			}

			break;
         }
        case GETDNS_RRTYPE_TXT:
        {
        	// txt_strings is a list
        	// TODO: not returning data as expected
        	// debug and see what is going on here.
			if (! process_list_bindata(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "txt_strings", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			break;
         }
        case GETDNS_RRTYPE_OPT:
         {
         	// options is a list
         	// list of value pairs
 			if (!process_list_dict(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "options", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			break;
          }

        case GETDNS_RRTYPE_APL:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "address_family", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			break;
         }

        case GETDNS_RRTYPE_SOA:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "mname", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "rname", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}

 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "serial", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}

 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "refresh", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}

 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "retry", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}

 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "expire", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}

 			break;
          }

        case GETDNS_RRTYPE_WKS:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "address", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "protocol", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "bitmap", resultslist,
							  this_component, response, component)) {
				return 0;
			}

			break;
         }
        case GETDNS_RRTYPE_PTR:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "ptrdname", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			break;
         }

        case GETDNS_RRTYPE_HINFO:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "cpu", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "os", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			break;
          }
        case GETDNS_RRTYPE_MINFO:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "rmailbox", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "emailbox", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			break;
         }
        case GETDNS_RRTYPE_RP:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "mbox_dname", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "txt_dname", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			break;
          }

        case GETDNS_RRTYPE_AFSDB:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "subtype", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "hostname", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			break;
          }

        case GETDNS_RRTYPE_X25:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "psdn_address", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			break;
          }

        case GETDNS_RRTYPE_ISDN:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "isdn_address", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			break;
          }

        case GETDNS_RRTYPE_RT:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "preference", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "intermediate_host", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			break;
          }

        case GETDNS_RRTYPE_NSAP:
          {
  			if (!process_data(rec_count, rr_count,
  							  this_type, name, class, ttl,
  							  "nsap", resultslist,
  							  this_component, response, component)) {
  				return 0;
  			}
  			break;
           }

        case GETDNS_RRTYPE_SIG:
          {
  			if (!process_data(rec_count, rr_count,
  							  this_type, name, class, ttl,
  							  "sig_obsolete", resultslist,
  							  this_component, response, component)) {
  				return 0;
  			}
  			break;
           }
        case GETDNS_RRTYPE_KEY:
          {
  			if (!process_data(rec_count, rr_count,
  							  this_type, name, class, ttl,
  							  "key_obsolete", resultslist,
  							  this_component, response, component)) {
  				return 0;
  			}
  			break;
           }
        case GETDNS_RRTYPE_NXT:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "nxt_obsolete", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_EID:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "eid_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_NIMLOC:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "nimloc_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_LOC:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "loc_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }

        case GETDNS_RRTYPE_DHCID:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "dhcid_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_NINFO:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "ninfo_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_RKEY:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "rkey_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_TALINK:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "talink_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_CDS:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "cds_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_SPF:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "text", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_UINFO:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "uinfo_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_UID:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "uid_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_GID:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "gid_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_UNSPEC:
            {
    			if (!process_data(rec_count, rr_count,
    							  this_type, name, class, ttl,
    							  "unspec_unknown", resultslist,
    							  this_component, response, component)) {
    				return 0;
    			}
    			break;
             }
        case GETDNS_RRTYPE_SINK:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "sink_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_TA:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "ta_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_MAILA:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "maila_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_MAILB:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "mailb_unknown", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_DNAME:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "target", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_A6:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "a6_obsolete", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_MG:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "mgmname", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_MR:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "newname", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }
        case GETDNS_RRTYPE_NULL:
           {
   			if (!process_data(rec_count, rr_count,
   							  this_type, name, class, ttl,
   							  "anything", resultslist,
   							  this_component, response, component)) {
   				return 0;
   			}
   			break;
            }

         case GETDNS_RRTYPE_DS:
         {
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "digest_type", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "key_tag", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}

 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "algorithm", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}

 			if (!process_data(rec_count, rr_count,
 							  this_type, name, class, ttl,
 							  "digest", resultslist,
 							  this_component, response, component)) {
 				return 0;
 			}
         }

        default:
        	return 0;
        }
   }

return 1;
}

/*
 * Pass in "header" to build the relavant sections
 */
int build_response_header(struct getdns_dict *response,
		                      PyObject *resultslist,
		                      struct getdns_dict *this_record)
{
    getdns_return_t this_ret;

	PyObject *headeritem = PyDict_New();
	// Get the header
	struct getdns_dict *header = NULL;
	this_ret = getdns_dict_get_dict(
			this_record, "header", &header);
	if (this_ret != GETDNS_RETURN_GOOD)  {
		error_exit("getdns_get_get_dict header failed", this_ret);
		return 0;
	}

    // Get the id
     uint32_t id;
     this_ret = getdns_dict_get_int(
    		 header, "id", &id);
     if (this_ret != GETDNS_RETURN_GOOD)  {
     	error_exit("getdns_dict_get_int failed", this_ret);
         return 0;
     }
     printf("header id = %d\n", id);
     // Get the status
      uint32_t status;
      this_ret = getdns_dict_get_int(
     		 header, "status", &status);
      if (this_ret != GETDNS_RETURN_GOOD)  {
      	  error_exit("getdns_dict_get_int failed", this_ret);
          //return 0;
      }
      printf("header status = %d\n", status);

    //get the opcode
      uint32_t opcode ;
  	this_ret = getdns_dict_get_bindata(
  			header, "opcode", &opcode);
  	if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME)
  	{
  		fprintf(stderr,
  			"Weird: invalid opcode in header Exiting.\n");
  		getdns_dict_destroy(response);
  		return 0;
  	}
  	printf("header opcode = %d\n", opcode);

return 1;
}

/*
 * Pass in "header" to build the relavant sections
 */
int build_response_question(struct getdns_dict *response,
		                      PyObject *resultslist,
		                      struct getdns_dict *this_record)
{
    getdns_return_t this_ret;

	PyObject *headeritem = PyDict_New();
	// Get the question
	struct getdns_dict *question = NULL;
	this_ret = getdns_dict_get_dict(
			this_record, "question", &question);
	if (this_ret != GETDNS_RETURN_GOOD)  {
		error_exit("getdns_get_get_dict header failed", this_ret);
		return NULL;
	}

    // Get the id
     uint32_t qtype;
     this_ret = getdns_dict_get_int(
    		 question, "qtype", &qtype);
     if (this_ret != GETDNS_RETURN_GOOD)  {
     	error_exit("getdns_dict_get_int failed", this_ret);
         return NULL;
     }
     printf("question qtype = %d\n", qtype);
     // Get the qclass
      uint32_t qclass;
      this_ret = getdns_dict_get_int(
     		 question, "qclass", &qclass);
      if (this_ret != GETDNS_RETURN_GOOD)  {
      	error_exit("getdns_dict_get_int failed", this_ret);
          return NULL;
      }
      printf("question qclass = %d\n", qclass);

      //get the qname
      struct getdns_bindata *qname = NULL;
  	this_ret = getdns_dict_get_bindata(
  			question, "qname", &qname);
  	if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME)
  	{
  		fprintf(stderr,
  			"Weird: invalid opcode in header Exiting.\n");
  		getdns_dict_destroy(response);
  		return 0;
  	}
  	printf("question qname = %s\n", getdns_display_ip_address(qname));

    return 1;
}

/**
 * reverse an IP address for PTR lookup
 * @param address_data IP address to reverse
 * @return NULL on allocation failure
 * @return reversed string on success, caller must free storage via call to free()
 */
char *
reverse_address(struct getdns_bindata *address_data)
{
    ldns_rdf *addr_rdf;
    ldns_rdf *rev_rdf;
    char *rev_str;

    if (address_data->size == 4)
        addr_rdf = ldns_rdf_new(LDNS_RDF_TYPE_A, 4, address_data->data);
    else if (address_data->size == 16)
        addr_rdf = ldns_rdf_new(LDNS_RDF_TYPE_AAAA, 16, address_data->data);
    else
        return NULL;
    if (!addr_rdf)
        return NULL;

    rev_rdf = ldns_rdf_address_reverse(addr_rdf);
    ldns_rdf_free(addr_rdf);
    if (!rev_rdf)
        return NULL;

    rev_str = ldns_rdf2str(rev_rdf);
    ldns_rdf_deep_free(rev_rdf);
    return rev_str;
}

