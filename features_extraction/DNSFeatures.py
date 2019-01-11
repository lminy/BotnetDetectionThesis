from DNSConnection import DNSConnection
import string
import csv
from collections import OrderedDict
import config as c
import numpy as np


class DNSFeatures(DNSConnection):
    alexa_top100 = list()
    alexa_top1k = list()
    alexa_top10k = list()
    alexa_top100k = list()
    alexa_top1m = list()

    def __init__(self, index):
        super(DNSFeatures, self).__init__(index)

    @staticmethod
    def get_alexa(filename):
        with open(filename, 'rb') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=' ', quoting=csv.QUOTE_MINIMAL)
            return csvreader.next()

    @staticmethod
    def load_all_top_alexa():
        DNSFeatures.alexa_top100 = DNSFeatures.get_alexa(c.alexa_folder + "alexa_top100.csv")
        DNSFeatures.alexa_top1k = DNSFeatures.get_alexa(c.alexa_folder + "alexa_top1k.csv")
        DNSFeatures.alexa_top10k = DNSFeatures.get_alexa(c.alexa_folder + "alexa_top10k.csv")
        DNSFeatures.alexa_top100k = DNSFeatures.get_alexa(c.alexa_folder + "alexa_top100k.csv")
        DNSFeatures.alexa_top1m = DNSFeatures.get_alexa(c.alexa_folder + "alexa_top1m.csv")



    def add_dns_record(self, dns_record):
        self.dns_records.append(dns_record)
        self.compute_classic_features(dns_record)

    def compute_classic_features(self, dns_record):

        if dns_record["answers"] != '-':
            self.answers.update(filter(is_ipv4, dns_record["answers"].split(',')))
        if dns_record["TTLs"] != '-':
            self.ttls += (map(float, dns_record["TTLs"].split(',')))



    ############
    # Features #
    ############

    ############ Anderson

    # -----------------------------------------------
    # 00. ---------- FQDN Length --------------------
    def get_FQDN_length(self):
        return len(self.FQDN)

    # -----------------------------------------------
    # 00. ---------- Domain name Length --------------------
    def get_domain_name_length(self):
        return len(self.domain_name)

    # ------------------------------------------------------------------
    # 00. ---------- number of numerical characters --------------------
    def get_number_of_numerical_chars(self):
        return len(filter(lambda c: c in string.digits, self.FQDN))

    # ------------------------------------------------------------------
    # 00. ---------- number of non-alphanumeric characters --------------------
    def get_number_of_non_alphanumeric_chars(self):
        alpha = string.ascii_letters + string.digits
        return len(filter(lambda c: c not in alpha and c != '.', self.FQDN))

    # ------------------------------------------------------------------
    # 00. ---------- alexa features --------------------
    def compute_alexa_features(self):
        alexa_features = OrderedDict()

        alexa_features["in_alexa_top100"] = 0
        alexa_features["in_alexa_top1k"] = 0
        alexa_features["in_alexa_top10k"] = 0
        alexa_features["in_alexa_top100k"] = 0
        alexa_features["in_alexa_top1m"] = 0
        alexa_features["not_in_alexa"] = 0

        if binarySearch(DNSFeatures.alexa_top100, self.domain_name):
            alexa_features["in_alexa_top100"] = 1
        elif binarySearch(DNSFeatures.alexa_top1k, self.domain_name):
            alexa_features["in_alexa_top1k"] = 1
        elif binarySearch(DNSFeatures.alexa_top10k, self.domain_name):
            alexa_features["in_alexa_top10k"] = 1
        elif binarySearch(DNSFeatures.alexa_top100k, self.domain_name):
            alexa_features["in_alexa_top100k"] = 1
        elif binarySearch(DNSFeatures.alexa_top1m, self.domain_name):
            alexa_features["in_alexa_top1m"] = 1
        else:
            alexa_features["not_in_alexa"] = 1
        return alexa_features

    ######### Mine

    # ------------------------------------------------------------------
    # 00. ---------- number of unique IP addresses in response --------------------
    def get_number_unique_IP_addresses_in_response(self):
        return len(self.answers)

    # ------------------------------------------------------------------
    # 00. ---------- number of subdomains --------------------
    def get_number_of_subdomains(self):
        return len(self.FQDN.split('.'))

    # ------------------------------------------------------------------
    # 00. ---------- average TTLs --------------------
    def get_average_ttls(self):
        if len(self.ttls) > 0:
            return sum(self.ttls) / len(self.ttls)
        else:
            return -1

    # ------------------------------------------------------------------
    # 00. ---------- std TTLs --------------------
    def get_std_ttls(self):
        if len(self.ttls) > 2:
            return np.std(self.ttls)
        else:
            return -1

    # ------------------------------------------------------------------
    # 00. ---------- min TTLs --------------------
    def get_min_ttls(self):
        return min(self.ttls) if len(self.ttls) > 0 else -1

    # ------------------------------------------------------------------
    # 00. ---------- max TTLs --------------------
    def get_max_ttls(self):
        return max(self.ttls) if len(self.ttls) > 0 else -1

    # ------------------------------------------------------------------
    # 00. ---------- number of hyphens in fqdn--------------------
    def get_number_of_hyphens_in_fqdn(self):
        return len(filter(lambda c: c == "-", self.FQDN))

    # ------------------------------------------------------------------
    # 00. ---------- length of the longest subdomain name--------------------
    def get_length_of_longest_subdomain_name(self):
        return max(map(len, self.FQDN.split('.')))

    # ------------------------------------------------------------------
    # 00. ---------- number of voyels --------------------
    def get_number_of_voyels_in_fqdn(self):
        voyels = "aeiou"
        return len(filter(lambda c: c in voyels, self.FQDN))

    # ------------------------------------------------------------------
    # 00. ---------- number of different chars in fqdn --------------------
    def get_number_of_different_chars_in_fqdn(self):
        chars = set()
        for c in self.FQDN:
            if c != ".":
                chars.add(c)
        return len(chars)

    # ------------------------------------------------------------------
    # 00. ---------- number of consonants --------------------
    def get_number_of_consonants_in_fqdn(self):
        consonants = "zrtypqsdfghjklmwxcvbn"
        return len(filter(lambda c: c in consonants, self.FQDN))

    # ------------------------------------------------------------------
    # 00. ---------- shannon entropy on 2ld --------------------
    def get_shannon_entropy_2ld(self):
        try:
            ent = entropy(self.subdomains[-2])
        except IndexError:
            print self.FQDN
            print self.subdomains
            raise
        return ent

    # ------------------------------------------------------------------
    # 00. ---------- shannon entropy on 3ld --------------------
    def get_shannon_entropy_3ld(self):
        if len(self.subdomains) > 2:
            return entropy(self.subdomains[-3])
        else:
            return -1



# UTILITIES

def binarySearch(alist, item):
    first = 0
    last = len(alist)-1
    found = False

    while first<=last and not found:
        pos = 0
        midpoint = (first + last)//2
        if alist[midpoint] == item:
            pos = midpoint
            found = True
        else:
            if item < alist[midpoint]:
                last = midpoint-1
            else:
                first = midpoint+1
    return found


def entropy(str):
    import math
    "Calculates the Shannon entropy of a string"

    # get probability of chars in string
    prob = [float(str.count(c)) / len(str) for c in dict.fromkeys(list(str))]

    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy

def is_ipv4(str):
    l = str.split('.')
    if len(l) != 4:
        return False
    try:
        ip = map(int, l)
    except ValueError:
        return False
    if len(filter(lambda x: 0 <= x <= 255, ip)) == 4:
        return True
    return False
