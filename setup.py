#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

packages=find_namespace_packages(include=['v3n0m.*'])

with open("README.md", "r") as descript:
    long_describe = descript.read()

version = '431'

setup(
    name="venom",
    version=version,
    description="Tool for Vulnerability Scanning & Pentesting",
    long_description=long_describe,
    long_description_content_type="text/markdown",
    author='NovaCygni',
    author_email='novacygni@hotmail.co.uk',
    url='https://github.com/v3n0m-Scanner/V3n0M-Scanner',
    license='GPL',
    package_dir={'v3n0m': 'src'},
    packages=['v3n0m'],

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6'],
    install_requires=[
        'termcolor==1.1.0',
        'aiohttp==3.7.4.post0',
        'asyncio==3.4.3',
        'bs4==0.0.1',
        'dnspython==2.1.0',
        'tqdm==4.61.2',
        'DateTime==4.3',
        'requests==2.26.0',
        'SocksiPy-branch==1.1',
        'httplib2==0.19.1'
      ]
)
