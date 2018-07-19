"""
This class stores all information for DNS records that have the same Domain name => called one DNSConnection
"""


class DNSConnection(object):

    def __init__(self, FQDN):
        self.FQDN = FQDN
        self.subdomains = self.FQDN.split('.')
        self.domain_name = '.'.join(self.subdomains[-2:])
        self.dns_records = list()
        self.ttls = list()
        self.answers = set()