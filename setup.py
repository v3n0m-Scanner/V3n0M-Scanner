#!/usr/bin/env python
from distutils.core import setup

setup(name = 'V3n0m',
    version = '3.4.0',
    description = "Popular linux version of Balthazar/NovaCygni's v3n0m scanner. Searches 18k+ dorks over 13 search engines.",
    author = 'NovaCygni, Architect, d4rkcat',
    author_email = 'novacygni@hotmail.co.uk, t3h4rch1t3ct@riseup.net, d4rkcat@yandex.com',
    url = 'https://github.com/v3n0m-Scanner/V3n0M-Scanner',
    package_dir = {'v3n0m': 'src'},
    packages = ['v3n0m'],
)
