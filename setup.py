#!/usr/bin/env python

from setuptools import setup

with open("README.md", "r") as descript:
    long_describe = descript.read()

setup(
    name='venom',
    version='425',
    description="Tool for Vulnerability Scanning & Pentesting",
    long_description=long_describe,
    long_description_content_type="text/markdown",
    author='NovaCygni',
    author_email='404 Not Found',
    url='https://github.com/v3n0m-Scanner/V3n0M-Scanner',
    package_dir={'v3n0m': 'src'},
    packages=['v3n0m']
)
