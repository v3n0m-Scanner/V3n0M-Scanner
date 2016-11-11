#This file is part of V3n0M
import argparse

PANELS = [
    {'name': 'cpanel', 'port': 2082, 'ssl': False},
    {'name': 'cpanel:ssl', 'port': 2083, 'ssl': True},
    {'name': 'whm', 'port': 2086, 'ssl': False},
    {'name': 'whm:ssl', 'port': 2087, 'ssl': True},
    {'name': 'cp-wmail', 'port': 2095, 'ssl': False},
    {'name': 'cp-wmail:ssl', 'port': 2096, 'ssl': True},
    {'name': 'directadmin', 'port': 2222, 'ssl': False},
    {'name': 'directadmin:ssl', 'port': 2222, 'ssl': True},
    {'name': 'virtuoso', 'port': 4643, 'ssl': False},
    {'name': 'virtuoso:ssl', 'port': 4643, 'ssl': True},
    {'name': 'dev', 'port': 8080, 'ssl': False},
    {'name': 'dev:ssl', 'port': 8080, 'ssl': True},
    {'name': 'plesk', 'port': 8087, 'ssl': False},
    {'name': 'plesk:ssl', 'port': 8443, 'ssl': True},
    {'name': 'urchin', 'port': 9999, 'ssl': False},
    {'name': 'urchin:ssl', 'port': 9999, 'ssl': True},
    {'name': 'webmin', 'port': 10000, 'ssl': False},
    {'name': 'webmin:ssl', 'port': 10000, 'ssl': True},
    {'name': 'ensim', 'port': 19638, 'ssl': False},
    {'name': 'ensim-ssel', 'port': 19638, 'ssl': True},
]


parser = argparse.ArgumentParser(
    description='Default behavior is scan everything.'
    + ' you can change that by specifying options.'
)

parser.add_argument(
    'target',
    metavar='DOMAIN',
    type=str,
    help='Domain name or file with name list, one per line'
)

scan_choices = 'subdomains, panels, crimeflare, mx'
parser.add_argument(
    '--scan',
    metavar='OPTION',
    nargs='*',
    choices=scan_choices.split(', '),
    default='subdomains crimeflare mx',
    help=scan_choices
)

parser.add_argument(
    '--sub',
    metavar='SUBDOMAIN',
    nargs='*',
    help='Scan specified subdomains'
)

panel_list = [pan['name'] for pan in PANELS]
parser.add_argument(
    '--pan',
    metavar='PANEL',
    nargs='*',
    help=str(panel_list)
)

parser.add_argument(
    '--dept',
    metavar='DEPT',
    choices=['simple', 'normal', 'full'],
    default='simple',
    help='[simple] scan top 30 subdomains, \
    [normal] top 200, \
    [full] scan over 9000 subs!!!'
)

args = parser.parse_args()
