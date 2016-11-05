import re


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
