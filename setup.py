from distutils.core import setup, Extension
import platform, os

platform_version = list(platform.python_version_tuple())[0:2]
if platform_version != ['2', '7']:
    print 'pygetdns requires Python version 2.7.  Exiting ... '
    os._exit(1)

long_description = ( 'pygetdns is a set of wrappers around the getdns'
                     'library (http://www.getdnsapi.net), providing'
                     'Python language bindings for the API')

CFLAGS = [ '-g' ]
module1 = Extension('getdns',
                    include_dirs = [ '/usr/local/include', ],
                    libraries = [ 'ldns', 'getdns', 'getdns_ext_event' ],
                    library_dirs = [ '/usr/local/lib' ],
                    sources = [ 'getdns.c', 'pygetdns_util.c' ],
                    runtime_library_dirs = [ '/usr/local/lib' ]
                    )

setup(name='PackageName',
      version='0.1.0',
      description='pygetdns Python bindings for getdns',
      long_description=long_description,
      url='http://www.getdnsapi.net',
      ext_modules = [ module1 ])
