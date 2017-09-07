from datetime import datetime
import pytz
from ExtractFeatures import ExtractFeatures


class ComputeFeatures(ExtractFeatures):

    def __init__(self):
        super(ComputeFeatures, self).__init__()
        self.file_time_name = str(datetime.strftime(datetime.now(pytz.utc), "%Y-%m-%d_%H-%M"))

    def add_cert_to_non_cert_conn(self):
        for key in self.connection_4_tuples.keys():

            """
            implementig feature: connection which have no certificate, but have at least one SNI,
            look, if in certificate_objects_dict is such servername with certificate
            """
            break_v = 0
            if self.connection_4_tuples[key].get_amount_diff_certificates() == 0:

                server_names = self.connection_4_tuples[key].get_SNI_list()
                if len(server_names) != 0:
                    for cert_serial in self.certificate_dict.keys():
                        for server_name in server_names:
                            x509_line = self.certificate_dict[cert_serial].contain_server_name(server_name)
                            if x509_line != 0:
                                self.connection_4_tuples[key].add_ssl_log_2(x509_line)
                                print "This Certificate was added after process:", "cert_serial:", cert_serial, "server_name=",server_name, "4-tuple=", key, "label:", self.connection_4_tuples[key].get_label_of_connection()
                                break_v = 1
                                break
                        if break_v == 1:
                            break

    def create_dataset(self):
        print "----------------------------------------"
        print "Creatind data ..."
        useful_ssl_flows = 0
        all_flows = 0
        space = '	'
        # with open("ExtractedData\\" + "conn_result.txt", 'w') as f:
        with open("./conn_result_" + self.file_time_name +".txt", 'w') as f:
            for key in self.connection_4_tuples.keys():
                f.write(str(key) + space +
                        str(self.connection_4_tuples[key].get_number_of_flows()) + space +
                        str(self.connection_4_tuples[key].get_average_of_duration()) + space +
                        str(self.connection_4_tuples[key].get_standard_deviation_duration()) + space +
                        str(self.connection_4_tuples[key].get_percent_of_standard_deviation_duration()) + space +
                        str(self.connection_4_tuples[key].get_total_size_of_flows_orig()) + space +
                        str(self.connection_4_tuples[key].get_total_size_of_flows_resp()) + space +
                        str(self.connection_4_tuples[key].get_ratio_of_sizes()) + space +
                        str(self.connection_4_tuples[key].get_percent_of_established_states()) + space +
                        str(self.connection_4_tuples[key].get_inbound_pckts()) + space +
                        str(self.connection_4_tuples[key].get_outbound_pckts()) + space +
                        str(self.connection_4_tuples[key].get_periodicity_average()) + space +
                        str(self.connection_4_tuples[key].get_periodicity_standart_deviation()) + space +
                        str(self.connection_4_tuples[key].get_ssl_ratio()) + space +
                        str(self.connection_4_tuples[key].get_average_public_key()) + space +
                        str(self.connection_4_tuples[key].get_tls_version_ratio()) + space +
                        str(self.connection_4_tuples[key].get_average_of_certificate_length()) + space +
                        str(self.connection_4_tuples[key].get_standart_deviation_cert_length()) + space +
                        str(self.connection_4_tuples[key].is_valid_certificate_during_capture()) + space +
                        str(self.connection_4_tuples[key].get_amount_diff_certificates()) + space +
                        str(self.connection_4_tuples[key].get_number_of_domains_in_certificate()) + space +
                        str(self.connection_4_tuples[key].get_certificate_ratio()) + space +
                        str(self.connection_4_tuples[key].get_number_of_certificate_path()) + space +
                        str(self.connection_4_tuples[key].x509_ssl_ratio()) + space +
                        str(self.connection_4_tuples[key].SNI_ssl_ratio()) + space +
                        str(self.connection_4_tuples[key].self_signed_ratio()) + space +
                        str(self.connection_4_tuples[key].is_SNIs_in_SNA_dns()) + space +
                        str(self.connection_4_tuples[key].get_SNI_equal_DstIP()) + space +
                        str(self.connection_4_tuples[key].is_CNs_in_SNA_dns()) + space +

                        # New features

                        str(self.connection_4_tuples[key].ratio_of_differ_SNI_in_ssl_log()) + space +
                        str(self.connection_4_tuples[key].ratio_of_differ_subject_in_ssl_log()) + space +
                        str(self.connection_4_tuples[key].ratio_of_differ_issuer_in_ssl_log()) + space +
                        str(self.connection_4_tuples[key].ratio_of_differ_subject_in_cert()) + space +
                        str(self.connection_4_tuples[key].ratio_of_differ_issuer_in_cert()) + space +
                        str(self.connection_4_tuples[key].ratio_of_differ_sandns_in_cert()) + space +
                        str(self.connection_4_tuples[key].ratio_of_same_subjects()) + space +
                        str(self.connection_4_tuples[key].ratio_of_same_issuer()) + space +
                        str(self.connection_4_tuples[key].ratio_is_same_CN_and_SNI()) + space +
                        str(self.connection_4_tuples[key].average_certificate_exponent()) + space +
                        str(self.connection_4_tuples[key].is_SNI_in_top_level_domain()) + space +
                        str(self.connection_4_tuples[key].ratio_certificate_path_error()) + space +
                        str(self.connection_4_tuples[key].ratio_missing_cert_in_cert_path()) + space +

                        self.connection_4_tuples[key].get_label_of_connection() +
                        "\n")
                useful_ssl_flows += self.connection_4_tuples[key].get_number_of_ssl_flows()
                all_flows += self.connection_4_tuples[key].get_number_of_flows()

        f.close()


    def save_dataset_information(self):
        print "----------------------------------------"
        print "Saving data ..."
        space = '	'
        # with open("ExtractedData\\" + "conn_result.txt", 'w') as f:
        with open("./dataset_info_" + self.file_time_name+".txt", 'w') as f:
            for key in self.dataset_inforamtion_dict.keys():
                f.write(str(key) + space +
                        str(self.dataset_inforamtion_dict[key].ssl_lines) + space +
                        str(self.dataset_inforamtion_dict[key].not_founded_x509_lines) + space +
                        str(self.dataset_inforamtion_dict[key].founded_x509_lines) + space +
                        str(self.dataset_inforamtion_dict[key].err_not_added_x509) +
                        "\n")
        f.close()


    """
    Statistic methods.
    """
    def print_statistic(self):
        print "-------------------------------------------"
        print "----------- Statistic ---------------------"
        print "-------------------------------------------"
        malware_certificates_array = []

        normal_tuples = 0
        malware_tuples = 0
        flows_together = 0
        flows_normal = 0
        flows_malware = 0
        cert_together = 0
        cert_normal = 0
        cert_malware = 0
        for tuple_key in self.connection_4_tuples.keys():
            conn_tuple = self.connection_4_tuples[tuple_key]
            flows_together += conn_tuple.get_number_of_ssl_flows()
            cert_together += len(conn_tuple.get_certificate_serial_dict().keys())
            # More normal labels and malware labels in one 4-tuple ?
            if conn_tuple.get_malware_label() != 0 and conn_tuple.get_normal_label() != 0:
                print "Error: More labels in one 4-tuples"
                # Same amout of labels in one 4-tuple?
                if conn_tuple.get_malware_label() == conn_tuple.get_normal_label():
                    print "Watch out baby, same amount of labels"
                    print "Normal:", conn_tuple.get_normal_label()
                    print "Malware:", conn_tuple.get_malware_label()

            if conn_tuple.is_malware():
                malware_tuples += 1
                flows_malware += conn_tuple.get_number_of_ssl_flows()
                cert_malware += len(conn_tuple.get_certificate_serial_dict().keys())

                malware_certificates_array += conn_tuple.get_x509_list()
            else:
                normal_tuples += 1
                flows_normal += conn_tuple.get_number_of_ssl_flows()
                cert_normal += len(conn_tuple.get_certificate_serial_dict().keys())
        print ""
        print "Connection 4-tuples:"
        print "All 4_tuples:", len(self.connection_4_tuples.keys())
        print "Normal 4-tuples:", normal_tuples
        print "Malware 4-tuples:", malware_tuples
        print ""
        print "Flows"
        print "All gathered flows:", flows_together
        print "Normal flows:", flows_normal
        print "Malware flows:", flows_malware
        print ""
        print "Certificates"
        print "All gathered certificates:", cert_together
        print "Normal certificates:", cert_normal
        print "Malware certificates:", cert_malware

        # Save malware certificates.
        self.save_malware_certificates(malware_certificates_array)

    def save_malware_certificates(self, x509_lines):
        with open('./malware_certificates', 'w') as f:
            for line in x509_lines:
                f.write(line + "\n")
            f.close()



    def compute_features(self):
        for key in self.connection_4_tuples.keys():
            print "---------- " + str(key) + "--------------"
            self.connection_4_tuples[key].get_number_of_flows()
            value = self.connection_4_tuples[key].get_average_of_duration()
            value = self.connection_4_tuples[key].get_standard_deviation_duration()
            value = self.connection_4_tuples[key].get_percent_of_standard_deviation_duration()
            value = self.connection_4_tuples[key].get_total_size_of_flows_orig()
            value = self.connection_4_tuples[key].get_total_size_of_flows_resp()
            value = self.connection_4_tuples[key].get_ratio_of_sizes()
            value = self.connection_4_tuples[key].get_percent_of_established_states()
            value = self.connection_4_tuples[key].get_inbound_pckts()
            value = self.connection_4_tuples[key].get_outbound_pckts()
            value = self.connection_4_tuples[key].get_periodicity_average()
            value = self.connection_4_tuples[key].get_periodicity_standart_deviation()
            value = self.connection_4_tuples[key].get_ssl_ratio()
            value = self.connection_4_tuples[key].get_average_public_key()
            value = self.connection_4_tuples[key].get_tls_version_ratio()
            value = self.connection_4_tuples[key].get_average_of_certificate_length()
            vaule = self.connection_4_tuples[key].get_standart_deviation_cert_length()
            value = self.connection_4_tuples[key].is_valid_certificate_during_capture()
            value = self.connection_4_tuples[key].get_amount_diff_certificates()
            value = self.connection_4_tuples[key].get_number_of_domains_in_certificate()
            value = self.connection_4_tuples[key].get_certificate_ratio()
            value = self.connection_4_tuples[key].get_number_of_certificate_path()
            value = self.connection_4_tuples[key].x509_ssl_ratio()
            value = self.connection_4_tuples[key].SNI_ssl_ratio()
            value = self.connection_4_tuples[key].self_signed_ratio()
            value = self.connection_4_tuples[key].is_SNIs_in_SNA_dns()
            value = self.connection_4_tuples[key].get_SNI_equal_DstIP()
            value = self.connection_4_tuples[key].is_CNs_in_SNA_dns()

            # self.connection_4_tuples[key].get_label_of_connection() +