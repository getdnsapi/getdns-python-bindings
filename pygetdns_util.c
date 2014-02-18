#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <getdns/getdns.h>
#include "pygetdns.h"


struct getdns_dict *
extensions_to_getdnsdict(PyDictObject *pydict)
{
    struct getdns_dict *newdict = 0;
    Py_ssize_t pos = 0;
    PyObject *key, *value;
    int  tmp_int;
    char *tmp_key;

    if (!PyDict_Check(pydict))  {
        PyErr_SetString(getdns_error, "Expected dict, didn't get one");
        return NULL;
    }
    newdict = getdns_dict_create();
    while (PyDict_Next((PyObject *)pydict, &pos, &key, &value))  {
        tmp_key = PyString_AsString(PyObject_Str(key));
        if ( (!strncmp(tmp_key, "dnssec_return_status", strlen("dnssec_return_status")))  ||
             (!strncmp(tmp_key, "return_both_v4_and_v6", strlen("return_both_v4_and_v6"))) )  {
            if (!PyInt_Check(value))  {
                PyErr_SetString(getdns_error, GETDNS_RETURN_EXTENSION_MISFORMAT_TEXT);
                return NULL;
            }
            tmp_int = (int)PyInt_AsLong(value);
            (void)getdns_dict_set_int(newdict, tmp_key, tmp_int);
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
decode_getdns_results_tree_response(struct getdns_dict *response)
{
    uint32_t error;
    struct getdns_list *addr_list;
    size_t n_addrs;
    getdns_return_t ret;
    PyObject *results;
    PyObject *resultslist;
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
    PyDict_SetItem(results, PyString_FromString("results_tree"), resultslist);
    return results;
}

/*
 * Helper function to process each answer type
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

	printf("process_data rrtype: %s type %u class %u ttl %u\n", rrtype, type, class, ttl);
    PyObject *resultitem = PyDict_New();

    this_ret = getdns_list_get_dict(
    		this_answer, rr_count, &this_rr);

    // Get the RDATA
    this_ret = getdns_dict_get_dict(
    		this_rr, "rdata", &this_rdata);

	this_ret = getdns_dict_get_bindata(
			this_rdata, rrtype, &this_a_record);
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
		printf("The %s address is %s\n", rrtype, this_address_str);

		// add items to answer
        PyObject *resultitem = PyDict_New();
        PyObject *rdata = PyDict_New();
        PyDict_SetItem(rdata, PyString_FromString(rrtype),
        		       PyString_FromString(this_address_str));

		PyObject *res1 = Py_BuildValue("{s:i,s:i,s:i,s:s,s:O}",
				"type", type, "class", class, "ttl", ttl, "name",
				(char *)name->data, "rdata", rdata);
		printf("The %s address is %s\n", rrtype, this_address_str);
		PyDict_SetItem(resultitem, PyString_FromString(component), res1);

		PyList_Append(resultslist, resultitem);
		free(this_address_str);
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
        case GETDNS_RRTYPE_TXT:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "txt_strings", resultslist,
							  this_component, response, component)) {
				return 0;
			}
			break;
         }
        case GETDNS_RRTYPE_APL:
        {
			if (!process_data(rec_count, rr_count,
							  this_type, name, class, ttl,
							  "address_family ", resultslist,
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

