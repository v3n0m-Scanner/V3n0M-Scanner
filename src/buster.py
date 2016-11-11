#This file is part of V3n0M
import urllib.request
from ipaddress import ip_address, IPv4Network, IPv6Network
import re,  urllib.request, urllib.error, urllib.parse
import socket
import http.client
import time


class CloudFlareNetwork:

    IPV4_NETWORKS = [
        IPv4Network(network)
        for network
        in open('lists/ips-v4').read().splitlines()
    ]

    IPV6_NETWORKS = [
        IPv6Network(network)
        for network
        in open('lists/ips-v6').read().splitlines()
    ]

    def in_range(self, ip):
        address = ip_address(ip)
        if not address:
            return False

        if address.version == 4:
            return self.in_network(address, self.IPV4_NETWORKS)
        else:
            return self.in_network(address, self.IPV6_NETWORKS)

    def in_network(self, host, networks):
        for network in networks:
            if host in network:
                return True

        return False



class MxRecords(object):

    records = {}

    def __init__(self, domain):
        self.domain = domain

    def __get__(self, obj=None, objtype=None):
        if self.domain in self.records:
            return self.records[self.domain]

        try:
            import dns.resolver
            mxs = dns.resolver.query(self.domain, 'MX')
        except:
            mxs = None

        if mxs:
            mx_priority = re.compile('\d* ')
            recs = [
                mx_priority.sub('', mx.to_text()[:-1])
                for mx in mxs
            ]
        else:
            recs = None

        self.records[self.domain] = recs
        return recs


class PageTitle(object):

    titles = {}

    def __init__(self, url, host=None):
        self.url = url
        self.host = host

        if host:
            self.id = self.url+':'+self.host
        else:
            self.id = self.url

    def __get__(self, obj=None, objtype=None):
        if self.id in self.titles:
            return self.titles[self.id]

        request = urllib.request.Request(url=self.url, headers=self.headers)

        try:
            html = urllib.request.urlopen(request, timeout=20).read()
        except:
            html = None

        title = self.parse_title(html)
        self.titles[self.id] = title
        return title

    def __set__(self, obj=None, val=None):
        raise AttributeError

    @property
    def headers(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; rv:36.0)' +
            'Gecko/200101 Firefox/36.0'
        }
        if self.host:
            headers['Host'] = self.host
        return headers

    def parse_title(self, html):
        html = str(html)
        get_title = re.compile(
            '<title>(.*?)</title>',
            re.IGNORECASE | re.DOTALL
        )
        search_result = get_title.search(html)

        if search_result:
            return search_result.group(1)
        else:
            return None

class HostByName(object):

    ips = {}

    def __init__(self, domain):
        self.domain = domain

    def __get__(self, obj=None, objtype=None):
        if self.domain in self.ips:
            return self.ips[self.domain]

        try:
            #ip = socket.gethostbyname(self.domain)
            ip = socket.getaddrinfo(self.domain, 80)[1][4][0]
        except:
            ip = None

        self.ips[self.domain] = ip
        return ip

    def __set__(self, obj=None, val=None):
        raise AttributeError



class Options:
    '''
    Scan even if the site is not protected
    '''
    SCAN_ANYWAY = False

    '''
    Do not check for matches. Just scan everything
    '''
    SCAN_EVERYTHING = False


PANELS = (
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
)


class HttpResponse(object):

    responses = {}

    def __init__(self, domain, port=None, timeout=10, ssl=False):
        self.domain = domain
        self.timeout = timeout
        self.ssl = ssl

        if port is None and ssl is False:
            self.port = 80
        elif port is None and ssl is True:
            self.port = 443
        else:
            self.port = port

    @property
    def id(self):
        return self.domain+':'+str(self.port)+(':ssl' if self.ssl else '')

    def __get__(self, obj=None, objtype=None):
        if self.id in self.responses:
            return self.responses[self.id]

        if self.ssl:
            connection = http.client.HTTPSConnection(
                self.domain,
                port=self.port,
                timeout=self.timeout
            )
        else:
            connection = http.client.HTTPConnection(
                self.domain,
                port=self.port,
                timeout=self.timeout
            )

        try:
            connection.request('HEAD', '/', None, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; rv:36.0)' +
                'Gecko/200101 Firefox/36.0'
                }
            )
            response = connection.getresponse()
        except:
            response = None

        connection.close()

        self.responses[self.id] = response
        return response

    def __set__(self, obj=None, val=None):
        raise AttributeError



class Target:

    def __init__(self, domain, name=None, port=None, timeout=10, ssl=False):
        self.domain = domain
        if name:
            self.name = name
        else:
            self.name = domain
        self.port = port
        self.timeout = timeout
        self.ssl = ssl

    @property
    def ip(self):
        return HostByName(self.domain).__get__()

    @property
    def response(self):
        return HttpResponse(
            self.domain, self.port, self.timeout, self.ssl
        ).__get__()

    @property
    def cloudflare_ip(self):
        net = CloudFlareNetwork()
        return net.in_range(self.ip)

    @property
    def cloudflare_ray(self):
        try:
            return self.response.getheader('CF-RAY')
        except:
            return None

    @property
    def enabled(self):
        try:
            if self.response.getheader('X-Powered-By'):
                return self.response.getheader('Server') \
                    + ' ' \
                    + self.response.getheader('X-Powered-By')
            else:
                return self.response.getheader('Server')
        except:
            return None

    @property
    def status(self):
        try:
            return self.response.status
        except:
            return None

    @property
    def reason(self):
        try:
            return self.response.reason
        except:
            return None

    @property
    def protected(self):
        return bool(self.cloudflare_ip) or bool(self.cloudflare_ray)

    def print_infos(self):
        print('['+self.name+'] '+self.domain)
        if not self.ip or self.status is None:
            return

        print(
            '> ip: %s (CF %s%s)' % (
                self.ip,
                'yes' if self.cloudflare_ip else 'no',
                ' RAY-'+self.cloudflare_ray if self.cloudflare_ray else ''
            )
        )

        if self.enabled:
            print(
                '> http: %s %s %s' % (
                    self.enabled+' -' if self.enabled else '',
                    self.status,
                    self.reason if self.reason else ''
                )
            )
        else:
            print(
                '> status: %s %s' % (self.status, self.reason)
            )




class CloudBuster:

    def __init__(self, domain):
        self.domain = domain
        self.target = {
            'main': None,
            'other': []
        }

    def resolving(self):
        if self.target['main']:
            if self.target['main'].ip:
                return True

        return False

    def check_ip(self, ip):
        net = CloudFlareNetwork()
        print(net.in_range(ip))

    def scan_main(self):
        target = Target(self.domain, 'target')
        target.print_infos()
        self.target['main'] = target

    def protected(self):
        if not self.target['main'] or type(self.target['main']) != Target:
            return False

        return self.target['main'].protected

    def scan_subdomains(self, subdomains=None, dept=None):
        if subdomains:
            toscan = subdomains
        else:
            toscan = open('lists/subdomains').read().splitlines()
            if dept:
                del toscan[dept:]

        targets = [
            Target(sub+'.'+self.domain, 'subdomain', timeout=5)
            for sub in toscan
        ]

        return self.scan(targets)

    def scan_panels(self, panels=None):
        targets = []

        for panel in PANELS:
            if not panels or panel['name'] in panels:
                target = Target(
                    domain=self.domain,
                    name=panel['name']+':'+str(panel['port']),
                    port=panel['port'],
                    timeout=2,
                    ssl=panel['ssl']
                )
                targets.append(target)

        return self.scan(targets)

    def scan_crimeflare(self):
        for line in open('lists/ipout'):
            if self.domain in line:
                crimeflare_ip = line.partition(' ')[2].rstrip()
                return self.scan([Target(crimeflare_ip, 'crimeflare')])

    def scan_mxs(self):
        mxs = MxRecords(self.domain).__get__()
        if mxs:
            targets = [
                Target(mx, 'mx', timeout=5)
                for mx in mxs
            ]
            return self.scan(targets)

    def scan(self, targets):
        for target in targets:
            target.print_infos()
            if self.is_interesting(target):
                self.target['other'].append(target)
                if self.match(target):
                    return target
        return None

    def is_interesting(self, target):
        return target.ip and not target.protected

    def match(self, possible_target):

        if Options.SCAN_EVERYTHING:
            return False

        main_target = self.target['main']

        main_target.title = PageTitle(
            'http://'+main_target.domain
        ).__get__()

        possible_target.title = PageTitle(
            'http://'+possible_target.ip,
            main_target.domain
        ).__get__()

        return main_target.title == possible_target.title

    def scan_summary(self):
        print('[SCAN SUMMARY]')

        if self.target['main']:
            print('Target: '+self.target['main'].domain)
            print('> ip: '+str(self.target['main'].ip))
            print('> protected: '+str(self.target['main'].protected))

        print('[interesting ips]')

        for host in self.list_interesting_hosts():
            print(host('ip')+' > '+host('description'))

    def list_interesting_hosts(self):
        hosts = []
        targets = self.target['other']

        for target in targets:
            if self.is_interesting(target) \
                    and target.status and target.status != 400:
                hosts.append({
                    'ip': target.ip,
                    'description': target.domain+' / '+target.name
                })

        return hosts
