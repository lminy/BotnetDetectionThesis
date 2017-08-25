

"""
This class stores all information for one "connection 4-tuple" object.
Also it computes features.
"""
import numpy
import socket


class Connection4tuple(object):

    def __init__(self, tuple_index):
        # basic 4-tuple
        self.tuple_index = tuple_index
        # list of flows
        self.ssl_flow_list = []
        self.not_ssl_flow_list = []
        self.x509_list = []
        self.uid_flow_dict = dict()
        self.ssl_logs_list = []
        self.malware_label = 0
        self.normal_label = 0
        self.average_duration_power = 0
        self.flow_which_has_duration_number = 0
        self.duration_list = []
        self.datsets_names_list = []

        # Connection Features
        self.number_of_ssl_flows = 0
        self.number_of_not_ssl_flows = 0
        self.number_of_ssl_logs = 0
        self.total_size_of_flows_resp = 0
        self.total_size_of_flows_orig = 0
        self.average_duration = 0
        # Flow features
        self.state_of_connection_dict = dict()
        self.inbound_packtes = 0
        self.outbound_packtes = 0
        # SSL flows
        self.version_of_ssl_dict = dict()
        self.version_of_ssl_cipher_dict = dict()
        self.certificate_path = dict()
        self.ssl_uids_list = []
        self.ssl_with_SNI = 0
        self.self_signed_cert = 0
        self.SNI_equal_DstIP = 0
        self.SNI_list = []
        # X509 features
        self.certificate_key_type_dict = dict()
        self.certificate_key_length_dict = dict()
        self.certificate_serial_dict = dict()
        self.certificate_valid_length = 0
        self.certificate_valid_length_pow = 0
        self.certificate_valid_number = 0
        self.not_valid_certificate_number = 0
        self.number_san_domains = 0
        self.number_san_domains_index = 0
        self.cert_percent_validity = []
        self.is_CN_in_SAN_list = []
        self.is_SNI_in_san_dns = []

        self.temp_list = []

        # ssl_flow = this flow has ssl log in ssl file
    def add_ssl_flow(self, flow, label):
        if 'Botnet' in label:
            self.malware_label += 1
        elif 'Normal' in label:
            self.normal_label += 1
        else:
            print "Error in Connectio_4_tuple: Here is label which is not normal or malware (botnet). It is:", label

        # Add this goodonesIPs to the list of goodonesIPs for this 4-tuple.
        self.ssl_flow_list.append(flow)
        self.compute_classic_features(flow)

    # ssl_flow = this flow does not have ssl log in ssl file
    def add_not_ssl_flow(self, flow, label):
        if 'Botnet' in label:
            self.malware_label += 1
        elif 'Normal' in label:
            self.normal_label += 1
        else:
            print "Error in Connectio_4_tuple: Here is label which is not normal or malware (botnet). It is:", label

        self.not_ssl_flow_list.append(flow)
        self.compute_classic_features(flow)

    def add_ssl_log(self, ssl_log, valid_x509_list, dataset_name):
        # compute each x509 line from valid_list (range is 0 or 1)
        for i in range(0, len(valid_x509_list)):
            # print valid_x509_list[i]
            self.compute_x509_features(valid_x509_list[i])
            # Feature 28: is SAN DNS part of SNI ?
            self.is_SNI_in_certificate(ssl_log, valid_x509_list[i])

        # compute ssl log
        self.compute_ssl_features(ssl_log)

        # add dasetname of this flow
        if not(dataset_name in self.datsets_names_list):
            self.datsets_names_list.append(dataset_name)

    def add_ssl_log_2(self, valid_x509_line):
        self.compute_x509_features(valid_x509_line)

    """
    --------- computing methods ---------------
    """
    def compute_classic_features(self, flow):
        # Split the goodonesIPs on elements.
        split = flow.split('	')
        try:
            self.uid_flow_dict[split[1]] += 1
            print "Error: more same conn uids in compute_ssl_features function !!!!!"
        except:
            self.uid_flow_dict[split[1]] = 1
        # Add state of connection to dict.
        self.add_state_of_connection(split[11])
        # split[9]-orig_bytes, split[10]-resp_bytes
        self.compute_size_of_flow(split[9], split[10])
        # analyze the duration (it can be '-')
        try:
            duration = float(split[8])
            self.process_duration(duration)
        except:
            pass

        # inbound and outbounds packets
        try:
            self.inbound_packtes += int(split[18])
        except:
            print "Error: resp pckts has bad formats."
        try:
            self.outbound_packtes += int(split[16])
        except:
            print "Error: resp pckts has bad formats."

        # perodicity
        # current_time = float(split[0])

    def compute_ssl_features(self, ssl_log):
        self.ssl_logs_list.append(ssl_log)
        split = ssl_log.split('	')
        self.ssl_uids_list.append(split[1])
        try:
            self.version_of_ssl_dict[split[6]] += 1
        except:
            self.version_of_ssl_dict[split[6]] = 1

        try:
            self.version_of_ssl_cipher_dict[split[7]] += 1
        except:
            self.version_of_ssl_cipher_dict[split[7]] = 1

        # Certificate path - number of signed certificate in first certificate
        if split[14] != '-':
            list_of_x509_uids = split[14].split(',')
            try:
                self.certificate_path[len(list_of_x509_uids)] += 1
            except:
                self.certificate_path[len(list_of_x509_uids)] = 1

        # SNI is known
        # split[9] == server name (SNI)
        server_name = split[9]
        if server_name != '-':
            self.ssl_with_SNI += 1

            # self.is_SNI_in_san_dns.append(self.is_SNI_in_certificates(server_name))

            self.SNI_list.append(server_name)
            if self.SNI_equal_DstIP != -1:
                try:
                    # check if servername is ip
                    socket.inet_aton(server_name)
                    dstIP = self.tuple_index[1]
                    print "Watch out: We have SNI as ip:", server_name, "and dst ip is:", dstIP
                    if dstIP != server_name:
                        self.SNI_equal_DstIP = -1
                    else:
                        self.SNI_equal_DstIP = 1
                except:
                    # server name is not IP.
                    pass
        try:
            if 'signed certificate in certificate' in split[20]:
                self.self_signed_cert += 1
                # if split[14] == '-':
                #     print "Self signed certificate without x509 uids !!!! Our feature architecture is bad !!!"
        except:
            pass



    """
    Computing of certificates features
    """
    def compute_x509_features(self, valid_x509_line):
        self.x509_list.append(valid_x509_line)
        self.is_CN_in_SAN(valid_x509_line)

        split = valid_x509_line.split('	')

        # check if certificate was valid durig the capture
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
            except:
                print "Certificate time length is broken."

        # certificate info
        # if certifcate is alredy here
        if not(split[3] in self.certificate_serial_dict.keys()):
            self.certificate_serial_dict[split[3]] = 1

            # self.add_cert_SAN_to_list(valid_x509_line)

            # certificate_key_length_dict
            if split[11] != '-':
                try:
                    self.certificate_key_length_dict[split[11]] += 1
                except:
                    self.certificate_key_length_dict[split[11]] = 1

            # certificate valid length
            if split[7] != '-' and split[6] != '-':
                try:
                    # certificate valid length
                    valid_length_sec = float(split[7]) - float(split[6])
                    valid_length_days_not_round = int((valid_length_sec / (3600.0 * 24.0)))
                    valid_length_days = round(valid_length_days_not_round, 2)
                    self.temp_list.append(valid_length_days)

                    self.certificate_valid_length += valid_length_days
                    self.certificate_valid_length_pow += pow(valid_length_days, 2)
                    self.certificate_valid_number += 1
                except:
                    pass

            # number of domain in san in x509
            if split[14] != '-':
                domains = len(split[14].split(','))
                self.number_san_domains += domains
                self.number_san_domains_index += 1

        # certificate is new, this connection does not contain this certificate
        else:
            self.certificate_serial_dict[split[3]] += 1

        # # certificate_key_type_dict
        # try:
        #     self.certificate_key_type_dict[split[10]] += 1
        # except:
        #     self.certificate_key_type_dict[split[10]] = 1


    "------------------- Methods --------------------------------------"
    """
    orig_bytes - The number of payload bytes the originator sent.
    resp_bytes - The number of payload bytes the responder sent.
    """
    def compute_size_of_flow(self, orig_bytes, resp_bytes):
        try:
            orig_bytes_number = int(orig_bytes)
        except:
            if orig_bytes != '-':
                print "Error: orig_bytes has bad format."
            orig_bytes_number = 0
        try:
            resp_bytes_number = int(resp_bytes)
        except:
            if resp_bytes != '-':
                print "Error: resp_bytes has bad format."
            resp_bytes_number = 0
        self.total_size_of_flows_orig += orig_bytes_number
        self.total_size_of_flows_resp += resp_bytes_number

    """
    Adding state of connetion of this goodonesIPs. Example: "S0", "S1"...
    index meaning
    S0, S1, SF, REJ, S2, S3, RSTO, RSTR, RSTOS0, RSTRH, SH, SHR, OTH,
    """
    def add_state_of_connection(self, state):
        if not(state in self.state_of_connection_dict.keys()):
            self.state_of_connection_dict[state] = 1
        else:
            self.state_of_connection_dict[state] += 1

    def process_duration(self, duration_value):
        self.flow_which_has_duration_number += 1
        self.duration_list.append(duration_value)
        # 1. EX of duration
        self.average_duration += duration_value
        # 2. EX^2
        self.average_duration_power += pow(duration_value, 2)

    def get_periodicity_list(self):
        final_flow_list = self.ssl_flow_list + self.not_ssl_flow_list
        flows_times_list = []
        for i in range(len(final_flow_list)):
            split = final_flow_list[i].split('	')
            flows_times_list.append(float(split[0]))
        sorted_times_list = sorted(flows_times_list)
        T2_1 = None
        T2_2 = None
        T3 = None
        last_flow = None
        time_diff_list = []
        for i in range(len(sorted_times_list)):
            if last_flow == None:
                last_flow = sorted_times_list[i]
                continue
            if T2_1 == None:
                T2_1 = sorted_times_list[i] - last_flow
                last_flow = sorted_times_list[i]
                continue

            T2_2 = sorted_times_list[i] - last_flow
            T3 = abs(T2_2 - T2_1)
            T2_1 = T2_2
            last_flow = sorted_times_list[i]
            time_diff_list.append(T3)
        return time_diff_list

    # def add_cert_SAN_to_list(self, x509_line):
    #     split = x509_line.split('	')
    #     CN_part = split[4]
    #     SAN_dns_list = split[14].split(',')
    #     for i in range(len(SAN_dns_list)):
    #         if '*' in SAN_dns_list[i]:
    #             SAN_dns_list[i] = SAN_dns_list[i].replace('*', '')
    #     self.certificate_SAN_list.append(SAN_dns_list)
    #
    # def is_SNI_in_certificates(self, SNI_name):
    #     for sna_dns_list in self.certificate_SAN_list:
    #         for san_dns in sna_dns_list:
    #             if san_dns in SNI_name:
    #                 return 1
    #     return 0

    def is_SNI_in_certificate(self, ssl_line, x509_line):
        ssl_split = ssl_line.split('	')
        x509_split = x509_line.split('	')

        server_name = ssl_split[9]
        if server_name != '-':
            # number of domain in san in x509
            if x509_split[14] != '-':
                SAN_dns_list = x509_split[14].split(',')
                for i in range(len(SAN_dns_list)):
                    if '*' in SAN_dns_list[i]:
                        SAN_dns_list[i] = SAN_dns_list[i].replace('*', '')
                hit = 0
                for san_dns in SAN_dns_list:
                    if san_dns in server_name:
                        hit = 1
                        break
                self.is_SNI_in_san_dns.append(hit)

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
            self.is_CN_in_SAN_list.append(hit_2)

    def get_ver_cipher_dict(self):
        return self.version_of_ssl_cipher_dict

    # to histogram
    def get_states_dict(self):
        return self.state_of_connection_dict

    # to histogram
    def get_certificate_key_length_dict(self):
        return self.certificate_key_length_dict

    # to histogram
    def get_version_of_ssl_dict(self):
        return self.version_of_ssl_dict

    # It will be number (number of distinct certificate in connection)
    def get_certificate_serial_dict(self):
        return self.certificate_serial_dict

    """
    ------------ get methods -----------------
    """
    def get_label_of_connection(self):
        if self.malware_label > self.normal_label:
            return "MALWARE"
        else:
            return "NORMAL"

    def is_malware(self):
        if self.malware_label > self.normal_label:
            return True

    def is_uid_in_dict(self, key):
        label = 0
        try:
            label = self.uid_flow_dict[key]
            return True
        except:
            return False

    def get_number_of_ssl_flows(self):
        self.number_of_ssl_flows = len(self.ssl_flow_list)
        return self.number_of_ssl_flows

    def get_number_of_not_ssl_flows(self):
        self.number_of_not_ssl_flows = len(self.not_ssl_flow_list)
        return self.number_of_not_ssl_flows

    def get_uid_flow_dict_length(self):
        # total = 0
        # for key in self.uid_flow_dict.keys():
        #     total += self.uid_flow_dict[key]
        # return total
        return len(self.uid_flow_dict)

    def get_uid_flow_dict(self):
        return self.uid_flow_dict

    def get_number_of_ssl_logs(self):
        self.number_of_ssl_logs = len(self.ssl_logs_list)
        return self.number_of_ssl_logs

    def get_ssl_logs_list(self):
        return self.ssl_logs_list

    def get_malware_label(self):
        return self.malware_label

    def get_normal_label(self):
        return self.normal_label

    def get_size_of_x509_list(self):
        return len(self.x509_list)

    def get_certificate_key_type_dict(self):
        return self.certificate_key_type_dict

    def get_ssl_uids_list(self):
        return self.ssl_uids_list

    def get_datsets_names_list(self):
        return self.datsets_names_list

    def get_SNI_list(self):
        return self.SNI_list
    """
    Zero exception method
    """
    def check_zero_dividing(self, number, text):
        if number == 0:
            print text