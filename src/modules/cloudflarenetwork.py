from ipaddress import ip_address, IPv4Network, IPv6Network
import os


def in_network(host, networks):
    for network in networks:
        if host in network:
            return True

    return False


class CloudFlareNetwork:

    path = os.path.dirname(str(os.path.realpath(__file__)))

    IPV4_NETWORKS = [
        IPv4Network(network)
        for network
        in open( path + '/lists/ips-v4').read().splitlines()
    ]

    IPV6_NETWORKS = [
        IPv6Network(network)
        for network
        in open( path + '/lists/ips-v6').read().splitlines()
    ]

    def in_range(self, ip):
        address = ip_address(ip)
        if not address:
            return False

        if address.version == 4:
            return in_network(address, self.IPV4_NETWORKS)
        else:
            return in_network(address, self.IPV6_NETWORKS)
