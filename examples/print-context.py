#!/usr/bin/env python
#

import getdns, sys, pprint

ctx = getdns.Context()
try:
    pprint.pprint(ctx.get_api_information())
except getdns.error as e:
    print(str(e))
    sys.exit(1)
