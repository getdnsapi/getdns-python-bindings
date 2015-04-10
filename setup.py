# Copyright (c) 2014, NLnet Labs, Verisign, Inc.
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# *  Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# *  Neither the names of the copyright holders nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.



from distutils.core import setup, Extension
import platform, os

platform_version = list(platform.python_version_tuple())[0:2]
if platform_version != ['2', '7']:
    print 'getdns requires Python version 2.7.  Exiting ... '
    os._exit(1)

long_description = ( 'getdns is a set of wrappers around the getdns'
                     'library (http://www.getdnsapi.net), providing'
                     'Python language bindings for the API')

CFLAGS = [ '-g' ]
getdns_module = Extension('getdns',
                    include_dirs = [ '/usr/local/include', ],
                    libraries = [ 'ldns', 'getdns', 'getdns_ext_event', 'event' ],
                    library_dirs = [ '/usr/local/lib' ],
                    sources = [ 'getdns.c', 'pygetdns_util.c', 'context.c',
                                'context_util.c', 'result.c' ],
                    runtime_library_dirs = [ '/usr/local/lib' ]
                    )

setup(name='getdns',
      version='0.3.1',
      description='getdns Python bindings for getdns',
      long_description=long_description,
      license='BSD',
      url='http://www.getdnsapi.net',
      ext_modules = [ getdns_module ])
