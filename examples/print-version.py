#!/usr/bin/env python

import getdns

ctx = getdns.Context()
try:
    print(ctx.get_api_information()['version_string'])
except getdns.error as e:
    print(str(e))
    sys.exit(1)
