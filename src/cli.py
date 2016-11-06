from panels import PANELS
import argparse

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
