from distutils.core import setup, Extension

CFLAGS = [ '-g' ]
module1 = Extension('getdns',
                    include_dirs = [ '/usr/local/include',
                                     ],
                    libraries = [ 'getdns' ],
                    library_dirs = [ '/usr/local/lib' ],
                    sources = [ 'getdns.c', 'pygetdns_util.c' ]
                    )

setup(name='PackageName',
      version='0.1',
      description='getdns interface',
      ext_modules = [ module1 ])
