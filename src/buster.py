from cloudflarenetwork import CloudFlareNetwork
from descriptor.mxrecords import MxRecords
from descriptor.pagetitle import PageTitle
from options import Options
from target import Target
from panels import PANELS


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
            print(host['ip']+' > '+host['description'])

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
