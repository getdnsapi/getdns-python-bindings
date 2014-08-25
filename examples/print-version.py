#!/usr/bin/env python

import getdns

ctx = getdns.Context()
print ctx.get_api_information()['version_string']
