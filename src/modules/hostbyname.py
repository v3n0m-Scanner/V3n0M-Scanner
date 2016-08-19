import socket


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
