#!/usr/bin/env python
#

import getdns, sys, pprint

ctx = getdns.Context()
pprint.pprint(ctx.get_api_information())
