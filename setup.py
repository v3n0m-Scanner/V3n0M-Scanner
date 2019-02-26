#!/usr/bin/env python
from distutils.core import setup

# noinspection PyBroadException
try:
    try:
        setup(name='V3n0M',
              version='425',
            description="Popular SQLi and Pentesting scanner in Python 3.6",
            author='NovaCygni',
            author_email='404 Not Found',
            url='https://github.com/v3n0m-Scanner/V3n0M-Scanner',
            package_dir={'v3n0m': 'src'},
            packages=['v3n0m'])
    except:
        from setuptools import setup

        setup(name='V3n0M',
              version='425',
            description="Popular SQLi and Pentesting scanner in Python 3.6",
            author='NovaCygni',
            author_email='404 Not Found',
            url='https://github.com/v3n0m-Scanner/V3n0M-Scanner',
            package_dir={'v3n0m': 'src'},
            packages=['v3n0m'])
except Exception as verb:
    print(str(verb))
