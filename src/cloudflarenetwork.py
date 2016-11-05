from ipaddress import ip_address, IPv4Network, IPv6Network


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
