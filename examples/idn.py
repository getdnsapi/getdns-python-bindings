#!/usr/bin/env python
# coding=utf-8

import getdns, sys

try:
    ulabel = getdns.alabel_to_ulabel('xn--p1acf')
    # Next line contains a utf-8 string
    alabel = getdns.ulabel_to_alabel('рус')
    ulabel1 = getdns.alabel_to_ulabel('xn--vermgensberatung-pwb')
    # Next line contains a utf-8 string
    alabel1 = getdns.ulabel_to_alabel('vermögensberatung')
except getdns.error as e:
    print(str(e))
    sys.exit(1)

print (ulabel)
print (alabel)
print (ulabel1)
print (alabel1)
