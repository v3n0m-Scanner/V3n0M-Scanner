#!/usr/bin/env python
from distutils.core import setup

setup(name='V3n0M',
      version='421',
      description="Popular SQLi and Pentesting scanner in Python 3.6",
      author='NovaCygni',
      author_email='404 Not Found',
      url='https://github.com/v3n0m-Scanner/V3n0M-Scanner',
      package_dir={'v3n0m': 'src'},
      packages=['v3n0m'], install_requires=['aiohttp', 'httplib2', 'socksipy-branch', 'requests', 'url', 'bs4',
                                            'pip', 'dnspython', 'tqdm', 'aioftp', 'termcolor']
      )
