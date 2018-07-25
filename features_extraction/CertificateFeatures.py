
class CertificateFeatures:

    def __init__(self, cert_serial, x509_line):
        self.servernames_dict = dict()
        self.cert_serial = cert_serial
        self.x509_line = x509_line
        self.malware_labels = 0
        self.normal_labels = 0

        self.not_valid_certificate_number = 0
        self.cert_percent_validity = []
        self.is_CN_in_SAN_f = -1
        self.certificate_key_length = -1
        self.number_san_domains = 0
        self.number_x509_lines = 0

        self.process_certificate(x509_line)

    def process_certificate(self, x509_line):
        self.is_CN_in_SAN(x509_line)

        split = x509_line.split('	')

        self.certificate_key_length = float(split[11])

        # number of domain in san in x509
        if split[14] != '-':
            domains = len(split[14].split(','))
            self.number_san_domains += domains

    def add_server_name(self, server_name, label):
        try:
            if self.servernames_dict[server_name]:
                pass
        except:
            self.servernames_dict[server_name] = 1

        if 'Botnet' in label:
            self.malware_labels += 1
        if 'Normal' in label:
            self.normal_labels += 1

    def contain_server_name(self, server_name):
        try:
            if self.servernames_dict[server_name]:
                return self.x509_line
        except:
            return 0

    def is_malware(self):
        if self.malware_labels != 0 and self.normal_labels != 0:
            print "Error: There are more malwares and more normals! Cert serial:", self.cert_serial
            print "     " + "malwares:", self.malware_labels, "normals", self.normal_labels
            print "     " + "SNI:"
            print self.servernames_dict.keys()

        if self.malware_labels > self.normal_labels:
            return True
        return False

    def add_x509_line(self, x509_line):
        split = x509_line.split('	')

        if split[7] != '-' and split[6] != '-':
            try:
                current_time = float(split[0])
                before_date = float(split[6])
                after_date = float(split[7])
                if current_time > after_date or current_time < before_date:
                    self.not_valid_certificate_number += 1
                    # print split[1], before_date, current_time, after_date

                # certificate ratio
                norm_after = after_date - before_date  # 31622399
                current_time_norm = current_time - before_date  # 12025263
                self.cert_percent_validity.append(current_time_norm / norm_after)

                self.number_x509_lines += 1
            except:
                print "Certificate time length is broken."


    def is_CN_in_SAN(self, x509_line):
        x509_split = x509_line.split('	')
        if x509_split[14] != '-':
            CN_part = x509_split[4]
            SAN_dns_list = x509_split[14].split(',')
            for i in range(len(SAN_dns_list)):
                if '*' in SAN_dns_list[i]:
                    SAN_dns_list[i] = SAN_dns_list[i].replace('*', '')
            hit_2 = 0
            for san_dns in SAN_dns_list:
                if san_dns in CN_part:
                    hit_2 = 1
                    break
            self.is_CN_in_SAN_f = hit_2

    def get_label_of_connection(self):
        if self.malware_labels > self.normal_labels:
            return "MALWARE"
        else:
            return "NORMAL"
    """
    ------------- FEATERES ---------------
    """
    # 1 CN is there
    # 0 is not there
    # -1 is not define
    def get_is_CN_in_SAN(self):
        return self.is_CN_in_SAN_f

    def get_certificate_key_length(self):
        return self.certificate_key_length

    def get_number_san_domains(self):
        return self.number_san_domains

    def get_number_of_server_name(self):
        return len(self.servernames_dict.keys())

    def get_not_valid_certificate_number(self):
        if self.number_x509_lines != 0:
            return self.not_valid_certificate_number / float(self.number_x509_lines)
        return -1

    def get_certificate_ratio(self):
        if len(self.cert_percent_validity) != 0:
            temp = 0
            for i in self.cert_percent_validity:
                temp += i
            return temp / float(len(self.cert_percent_validity))
        else:
            return -1