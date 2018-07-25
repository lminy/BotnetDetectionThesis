import main_tools
from Connection4tuple import Connection4tuple


class ConnectionFeatures(Connection4tuple):

    def __init__(self, tuple_index):
        super(ConnectionFeatures, self).__init__(tuple_index)

    """
    ---------- Get Feature -------------------
    """
    # ---------------------------------------------------
    # 01. ---------- Number of flows --------------------
    def get_number_of_flows(self):
        return self.get_number_of_ssl_flows() + self.get_number_of_not_ssl_flows()

    # ---------------------------------------------------
    # ---------- Duration of flows ----------------------
    # 02. Average
    def get_average_of_duration(self):
        # self.check_zero_dividing(self.flow_which_has_duration_number, "flow_which_has_duration_number is 0 !!!")
        if self.flow_which_has_duration_number != 0:
            return self.average_duration / float(self.flow_which_has_duration_number)
        return -1

    # 03. Standard deviation
    def get_standard_deviation_duration(self):
        # self.check_zero_dividing(self.flow_which_has_duration_number, "flow_which_has_duration_number is 0 !!!")
        # EX = self.average_duration / float(self.flow_which_has_duration_number)
        # EX2 = self.average_duration_power / float(self.flow_which_has_duration_number) # E(X^2)
        # DX = EX2 - EX*EX
        # return pow(DX, 0.5)
        if len(self.duration_list) != 0 and len(self.duration_list) > 2:
            return main_tools.std(self.duration_list)
        return -1

    # 04. Percent of flows which are bigger or less than standard deviation with average
    def get_percent_of_standard_deviation_duration(self):
        # self.check_zero_dividing(self.flow_which_has_duration_number, "flow_which_has_duration_number is 0 !!!")
        if len(self.duration_list) != 0:
            out_of_bounds = 0
            lower_level = self.get_average_of_duration() - self.get_standard_deviation_duration()
            upper_level = self.get_average_of_duration() + self.get_standard_deviation_duration()
            for i in range(len(self.duration_list)):
                if self.duration_list[i] < lower_level:
                    out_of_bounds += 1
                elif self.duration_list[i] > upper_level:
                    out_of_bounds += 1

            return out_of_bounds / float(self.flow_which_has_duration_number)
        return -1

    # -------------------------------------------------------------------
    # 05 -------- Total payload size of flows the originator sent --------
    def get_total_size_of_flows_orig(self):
        return self.total_size_of_flows_orig

    # ------------------------------------------------------------------
    # 06 -------- Total payload size of flows the responder sent --------
    def get_total_size_of_flows_resp(self):
        return self.total_size_of_flows_resp

    # ---------------------------------------------------------------------------
    # 07 ------ Ratio of responder payload sizes and originator payload sizes ----
    def get_ratio_of_sizes(self):
        # self.check_zero_dividing(self.total_size_of_flows_orig, "Original size is 0 !!!")
        if self.total_size_of_flows_orig != 0:
            return self.total_size_of_flows_resp / float(self.total_size_of_flows_orig)
        return -1

    # --------------------------------------------------------------------
    # ------ State of connection -----------------------------------------
    # 08 Percent of established connection
    def get_percent_of_established_states(self):
        establihed_states = 0
        total_value_states = 0
        for key in self.state_of_connection_dict.keys():
            total_value_states += self.state_of_connection_dict[key]
        if total_value_states != 0:
            establihed_states += self.state_of_connection_dict.get('SF', 0)
            establihed_states += self.state_of_connection_dict.get('S1', 0)
            establihed_states += self.state_of_connection_dict.get('S2', 0)
            establihed_states += self.state_of_connection_dict.get('S3', 0)
            establihed_states += self.state_of_connection_dict.get('RSTO', 0)  # delete this
            establihed_states += self.state_of_connection_dict.get('RSTR', 0)  # delete this
            return (establihed_states / float(total_value_states))
        return -1

    """
    These functions are not used.
    """
    # 09 - return 4 items
    # def get_based_states_ratio(self):
    #     SF_S1 = self.state_of_connection_dict['SF'] + self.state_of_connection_dict['S1']
    #     S0 = self.state_of_connection_dict['S0']
    #     OTH = self.state_of_connection_dict['OTH']
    #     REJ = self.state_of_connection_dict['REJ']
    #     biggest = max(SF_S1, S0, OTH, REJ) / 100.0
    #     return SF_S1 / float(biggest), S0 / float(biggest), OTH / float(biggest), REJ / float(biggest)
    #
    # # 10 - return 6 items
    # def get_extended_states_ratio(self):
    #     SF_S1 = self.state_of_connection_dict['SF'] + self.state_of_connection_dict['S1']
    #     S0 = self.state_of_connection_dict['S0']
    #     OTH = self.state_of_connection_dict['OTH']
    #     REJ = self.state_of_connection_dict['REJ']
    #     RSTO_1 = self.state_of_connection_dict['RSTO'] + self.state_of_connection_dict['RSTR'] + self.state_of_connection_dict['S2'] + self.state_of_connection_dict['S3']
    #     RSTO_2 = self.state_of_connection_dict['RSTOS0'] + self.state_of_connection_dict['RSTRH'] + self.state_of_connection_dict['SH'] + self.state_of_connection_dict['SHR']
    #     biggest = max(SF_S1, S0, OTH, REJ, RSTO_1, RSTO_2) / 100.0
    #     return SF_S1 / float(biggest), S0 / float(biggest), OTH / float(biggest), REJ / float(biggest), RSTO_1 / float(biggest), RSTO_2 / float(biggest)

    # 11 inbound packets == resp_pkts (18)
    # Number of packets that the responder sent.
    def get_inbound_pckts(self):
        return self.inbound_packtes

    # 12 outbound packets == orig_pkts (16)
    def get_outbound_pckts(self):
        return self.outbound_packtes

    # Periodicity
    # 13 Average of periodicity
    def get_periodicity_average(self):
        per_list = self.get_periodicity_list()
        sum = 0
        for i in range(len(per_list)):
            sum += per_list[i]
        if len(per_list) != 0:
            return sum / float(len(per_list))
        # print "periodicity list is zero. Number of flows:", self.get_number_of_flows()
        return -1

    # 14
    def get_periodicity_standart_deviation(self):
        per_list = self.get_periodicity_list()
        if len(per_list) != 0 and len(per_list) > 2:
            # sum = 0
            # for i in range(len(per_list)):
            #     sum += pow(per_list[i], 2)
            # EX2 = sum / float(len(per_list))
            # DX = EX2 - EX * EX
            # return pow(DX, 0.5)
            return main_tools.std(self.get_periodicity_list())
        return -1

    # -----------------------------------------------------
    # 15 ------ Ratio of not ssl flows and ssl flows -------
    def get_ssl_ratio(self):
        self.check_zero_dividing(len(self.ssl_flow_list), "Original size is 0 !!!")
        return len(self.not_ssl_flow_list) / float(len(self.ssl_flow_list))

    # 16 Average Public key lenghts
    # certificate feature
    def get_average_public_key(self):
        total = 0
        index = 0
        for key in self.certificate_key_length_dict.keys():
            total += self.certificate_key_length_dict[key] * int(key)
            index += 1
        if index != 0:
            return total / float(index)
        return -1

    # ------------------------------------------------------
    # 17  Version of ssl ratio
    def get_tls_version_ratio(self):
        tls = 0
        ssl = 0
        total = 0
        for key in self.version_of_ssl_dict.keys():
            if 'tls' in key.lower():
                tls += self.version_of_ssl_dict[key]
            elif 'ssl' in key.lower():
                ssl += self.version_of_ssl_dict[key]
            total += self.version_of_ssl_dict[key]
        if total != 0:
            return tls / float(total)
        return -1

    # ----------------------------------------------
    # Certificate validation length
    # 18 Average of certificate length
    # certificate_valid_length = sum of certificate valid length in days
    # certificate_valid_number = number of certificate*
    def get_average_of_certificate_length(self):
        # self.check_zero_dividing(self.certificate_valid_number, "certificate_valid_number is 0 !!!")
        if self.certificate_valid_number != 0:
            if main_tools.mean(self.temp_list) != self.certificate_valid_length / float(self.certificate_valid_number):
                print "Error: numpy mean and mean by hand are not same."
            return self.certificate_valid_length / float(self.certificate_valid_number)
        return -1

    # 19
    def get_standart_deviation_cert_length(self):
        # self.check_zero_dividing(self.certificate_valid_number, "certificate_valid_number is 0 !!!")
        if self.certificate_valid_number != 0:
            EX = self.certificate_valid_length / self.certificate_valid_number
            EX2 = self.certificate_valid_length_pow / self.certificate_valid_number
            DX = EX2 - (EX * EX)
            # if DX < 0:
            #     print "EX:", (EX*EX)
            #     print "EX2:", EX2
            #     print "DX:", DX
            #     print self.temp_list
            #     print "std:", numpy.std(self.temp_list)
            #     print len(self.x509_list)
            return pow(DX, 0.5)
        return -1

    # ---------------------------------------------
    # 20 Validity of the certificate during the capture
    # certificate feature
    # 0 == no certficate was out of validity range
    def is_valid_certificate_during_capture(self):
        if len(self.cert_percent_validity) != 0:
            return self.not_valid_certificate_number
        return -1

    # 21 Amount of different certificates
    # certificate feature
    def get_amount_diff_certificates(self):
        return len(self.certificate_serial_dict.keys())

    # -------------------------------------------------------
    # 22 Number of domains in certificate
    # certificate feature
    def get_number_of_domains_in_certificate(self):
        if self.number_san_domains_index != 0:
            return self.number_san_domains / float(self.number_san_domains_index)
        return -1

    # 23 Certificate ratio
    # certificate feature
    # List of length of certificate validity length.
    def get_certificate_ratio(self):
        if len(self.cert_percent_validity) != 0:
            temp = 0
            for value in self.cert_percent_validity:
                temp += value
            return temp / float(len(self.cert_percent_validity))
        else:
            return -1

    # 24 Certificate path
    # number of signed certificate in our first certificate
    # It is EX (vazeny prumer)
    def get_number_of_certificate_path(self):
        up = 0
        down = 0
        for key in self.certificate_path.keys():
            up += int(key) * self.certificate_path[key]
            down += self.certificate_path[key]
        if down != 0:
            return up/float(down)
        return -1

    # 25 x509/ssl ratio
    # ratio about how many ssl log has x509 information in this connection
    def x509_ssl_ratio(self):
        if len(self.ssl_logs_list) == 0:
            return -1
        return len(self.x509_list) / float(len(self.ssl_logs_list))

    # 26 SNI and SSL ratio
    # ratio, how many ssl flows have SNI (server name)
    def SNI_ssl_ratio(self):
        return self.ssl_with_SNI / float(len(self.ssl_logs_list))

    # 27 Self_signed cert and all cert ratio
    def self_signed_ratio(self):
        # number_of_certificate = len(self.certificate_serial_dict.keys())
        if len(self.ssl_logs_list) != 0:
            return self.self_signed_cert / float(len(self.ssl_logs_list))
        return -1

    # 28 Is there any SNI, which not in san.dns ?
    def is_SNIs_in_SNA_dns(self):
        if len(self.is_SNI_in_san_dns) != 0:
            for a in self.is_SNI_in_san_dns:
                if a == 0:
                    return 0
            return 1
        return -1

    # 29 if SNI is IP, so dst is same ip?
    def get_SNI_equal_DstIP(self):
        return self.SNI_equal_DstIP

    # 30 Is there any CN, which not in san.dns ?
    def is_CNs_in_SNA_dns(self):
        if len(self.is_CN_in_SAN_list) != 0:
            for a in self.is_CN_in_SAN_list:
                if a == 0:
                    return 0
            return 1
        return -1


    """
    -----------------  New Features ------------------ 
    """
    # 31 How many ssl lines has different SNI ?
    def ratio_of_differ_SNI_in_ssl_log(self):
        # Delete stars.
        for i in range(0, len(self.SNI_list)):
            if '*' in self.SNI_list[i]:
                self.SNI_list[i] = self.SNI_list[i].replace('*', '')

        return compute_differents_in_lines(self.SNI_list)

    # 32 How many ssl lines has different subject
    def ratio_of_differ_subject_in_ssl_log(self):
        return compute_differents_in_lines(self.subject_ssl_list)

    # 33 How many ssl lines has differ issuer
    def ratio_of_differ_issuer_in_ssl_log(self):
        return compute_differents_in_lines(self.issuer_ssl_list)

    # 34 How many cert has differ subject
    def ratio_of_differ_subject_in_cert(self):
        return compute_differents_in_lines(self.subject_x509_list)

    # 35 How many cert has differ issuer
    def ratio_of_differ_issuer_in_cert(self):
        return compute_differents_in_lines(self.issuer_x509_list)

    # 36 How many cert has differ san dns
    def ratio_of_differ_sandns_in_cert(self):
        return compute_differents_in_lines(self.san_x509_list)

    # 37 Do ssl and x509 lines have same subjects?
    def ratio_of_same_subjects(self):
        if len(self.x509_list) == 0:
            return -1
        return self.subject_diff / float(len(self.x509_list))

    # 38 Do ssl and x509 lines have same issuer?
    def ratio_of_same_issuer(self):
        if len(self.x509_list) == 0:
            return -1
        return self.issuer_diff / float(len(self.x509_list))

    # 39 Is SNI and CN same?
    def ratio_is_same_CN_and_SNI(self):
        if len(self.x509_list) == 0:
            return -1
        return self.SNI_is_in_CN / float(len(self.x509_list))

    # 40 Certificate exponent average
    def average_certificate_exponent(self):
        if len(self.certificate_serial_dict.keys()) == 0:
            return -1
        return self.certificate_exponent / float(len(self.certificate_serial_dict.keys()))

    # 41 Is server name in top-level-domain ?
    def is_SNI_in_top_level_domain(self):
        if self.ssl_with_SNI == 0:
            return -1
        return self.top_level_domain_error / float(self.ssl_with_SNI)

    # 42 Is certificate path right ? (issuer of first certificate is subject in second cert...)
    def ratio_certificate_path_error(self):
        if len(self.ssl_logs_list):
            return -1
        return self.certificate_path_error / float(len(self.ssl_logs_list))

    # 43 Missing certificate in certificate path.
    def ratio_missing_cert_in_cert_path(self):
        if len(self.ssl_logs_list):
            return -1
        return self.missing_cert_in_cert_path / float(len(self.ssl_logs_list))


"""
------- Computation method ---------
"""
def compute_differents_in_lines(array):
    _dict = dict()
    for item in array:
        try:
            _dict[item] += 1
        except:
            _dict[item] = 1

    if len(array) == 0:
        return -1.0
    if len(_dict.keys()) == 1:
        return 0.0
    return len(_dict.keys()) / float(len(array))