#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include "pygetdns.h"


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
 * Helper function to process each answer type
 */
int process_data(size_t rec_count,
		         size_t rr_count,
		         char* type,
		         PyObject* resultslist,
		         struct getdns_list *this_answer,
		         struct getdns_dict *response)
{
    getdns_return_t this_ret;
    struct getdns_dict *this_rr = NULL;
    struct getdns_dict *this_rdata = NULL;
	struct getdns_bindata *this_a_record = NULL;

	printf("process_data %s \n", type);
    PyObject *resultitem = PyDict_New();

    this_ret = getdns_list_get_dict(
    		this_answer, rr_count, &this_rr);
    /* Get the RDATA */

    this_ret = getdns_dict_get_dict(
    		this_rr, "rdata", &this_rdata);

	this_ret = getdns_dict_get_bindata(
			this_rdata, type, &this_a_record);
	if (this_ret == GETDNS_RETURN_NO_SUCH_DICT_NAME)
	{
		fprintf(stderr,
			"Weird: the A record at %d in record at %d "
			"had no address. Exiting.\n",
			(int) rr_count, (int) rec_count);
		getdns_dict_destroy(response);
		return 0;
	}
	char *this_address_str = getdns_display_ip_address(this_a_record);
	if (this_address_str) {
		printf("The %s address is %s\n", type, this_address_str);
		PyObject *addr1 = PyDict_New();
		PyDict_SetItem(addr1, PyString_FromString(type),
			  PyString_FromString(this_address_str));
		PyDict_SetItem(resultitem, PyString_FromString("answer"), addr1);
		PyList_Append(resultslist, resultitem);
		free(this_address_str);
	}
	return 1;
}

/*
 * Error checking helper
 */
void error_exit(char* msg, getdns_return_t ret)
{
    char error_str[512];
    if (ret != GETDNS_RETURN_GOOD)  {
        sprintf(error_str, "%s: %d", msg, ret);
        PyErr_SetString(getdns_error, error_str);
    }
}

/*
 * Helper function for constructing a tree of PyDicts for the response.
 */
PyObject *
decode_getdns_results_tree_response(struct getdns_dict *response)
{
    uint32_t error;
    struct getdns_list *addr_list;
    size_t n_addrs;
    getdns_return_t ret;
    PyObject *results;
    PyObject *resultslist;
    size_t rr_count = 0;
    size_t rec_count = 0;
    getdns_return_t this_ret;

    printf("decode_getdns_results_tree_response\n");
    (void)getdns_dict_get_int(response, "status", &error);
    if (error != GETDNS_RESPSTATUS_GOOD)  {
    	error_exit("No answers, return value", error);
        return NULL;
    }
    printf("decode_getdns_results_tree_response1\n");

    if ((ret = getdns_dict_get_list(response, "replies_tree",
                                    &addr_list)) != GETDNS_RETURN_GOOD)  {
    	error_exit("Extracting answers failed", ret);
        return NULL;
    }
    printf("decode_getdns_results_tree_response2\n");

    results = PyDict_New();
    if ((resultslist = PyList_New(0)) == NULL)  {
       error_exit("Unable to allocate response list", 0);
        return NULL;
    }
    printf("decode_getdns_results_tree_response3\n");

    (void)getdns_list_get_length(addr_list, &n_addrs);

    printf("Num of addrs = %lu\n", n_addrs);
    for ( rec_count = 0; rec_count < n_addrs; ++rec_count )
    {

	    struct getdns_dict * this_record;
	    //TODO: Handle errors for below 2 functions
        this_ret = getdns_list_get_dict(
        		addr_list, rec_count, &this_record);
        /* Get the answer section */
        struct getdns_list * this_answer;
        this_ret = getdns_dict_get_list(
        		this_record, "answer", &this_answer);

        /* Get each RR in the answer section */
        size_t num_rrs;
        this_ret = getdns_list_get_length(this_answer, &num_rrs);
        printf("Num of rrs = %lu\n", num_rrs);

        for (rr_count = 0; rr_count < num_rrs; ++rr_count )
        {
            //PyObject *resultitem = PyDict_New();
            struct getdns_dict *this_rr = NULL;
            //TODO: Handle errors from the below.
            this_ret = getdns_list_get_dict(
            		this_answer, rr_count, &this_rr);
            if (this_ret != GETDNS_RETURN_GOOD)  {
                error_exit("getdns_list_get_dict failed", this_ret);
                return NULL;
            }
            /* Get the RDATA */
            struct getdns_dict * this_rdata = NULL;
            this_ret = getdns_dict_get_dict(
            		this_rr, "rdata", &this_rdata);
            if (this_ret != GETDNS_RETURN_GOOD)  {
            	error_exit("getdns_get_get_dict rdata failed", this_ret);
                return NULL;
            }

            /* Get the RDATA type */
            uint32_t this_type;
            this_ret = getdns_dict_get_int(
            		this_rr, "type", &this_type);
            if (this_ret != GETDNS_RETURN_GOOD)  {
            	error_exit("getdns_dict_get_int failed", this_ret);
                return NULL;
            }

            printf("Type = %d\n", this_type);
            /* If it is a valid RR stash the value in PyObject */
            switch (this_type) {

            case GETDNS_RRTYPE_A:
            {
            	if (!process_data(rec_count, rr_count,
            			          "ipv4_address", resultslist,
            			          this_answer, response)) {
            		return NULL;
            	}
            	break;
            }
            case GETDNS_RRTYPE_AAAA:
           {
				if (!process_data(rec_count, rr_count,
						          "ipv6_address", resultslist,
								  this_answer, response)) {
					return NULL;
				}
				break;
            }
            case GETDNS_RRTYPE_NS:
           {
				if (!process_data(rec_count, rr_count,
						          "nsdname", resultslist,
								  this_answer, response)) {
					return NULL;
				}
				break;
            }
            case GETDNS_RRTYPE_MD:
            case GETDNS_RRTYPE_MF:
            case GETDNS_RRTYPE_MB:
           {
				if (!process_data(rec_count, rr_count,
						          "madname", resultslist,
								  this_answer, response)) {
					return NULL;
				}
				break;
            }
            case GETDNS_RRTYPE_CNAME:
            {
 				if (!process_data(rec_count, rr_count,
 						          "cname", resultslist,
 								  this_answer, response)) {
 					return NULL;
 				}
 				break;
             }
            case GETDNS_RRTYPE_TXT:
            {
 				if (!process_data(rec_count, rr_count,
 						          "txt_strings", resultslist,
 								  this_answer, response)) {
 					return NULL;
 				}
 				break;
             }
            case GETDNS_RRTYPE_APL:
            {
 				if (!process_data(rec_count, rr_count,
 						          "address_family ", resultslist,
 								  this_answer, response)) {
 					return NULL;
 				}
 				break;
             }

            default:
            	return NULL;
            }
       }
    }

    PyDict_SetItem(results, PyString_FromString("results_tree"), resultslist);
    return results;
}

