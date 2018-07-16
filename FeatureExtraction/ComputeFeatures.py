from datetime import datetime
import pytz
from ExtractFeatures import ExtractFeatures
import config as c


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
    """
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
    """

    def create_dataset(self):
        import csv
        from collections import OrderedDict

        with open(c.model_folder + 'features.csv', 'wb') as csvfile:
            line = 0
            for key, con4tuple in self.connection_4_tuples.iteritems():
                features = OrderedDict()
                features["key"] = " ".join(key)
                features["number_of_flows"] = con4tuple.get_number_of_flows()
                features["average_of_duration"] = con4tuple.get_average_of_duration()
                features["standard_deviation_duration"] = con4tuple.get_standard_deviation_duration()
                features["percent_of_standard_deviation_duration"] = con4tuple.get_percent_of_standard_deviation_duration()
                features["total_size_of_flows_orig"] = con4tuple.get_total_size_of_flows_orig()
                features["total_size_of_flows_resp"] = con4tuple.get_total_size_of_flows_resp()
                features["ratio_of_sizes"] = con4tuple.get_ratio_of_sizes()
                features["percent_of_established_states"] = con4tuple.get_percent_of_established_states()
                features["inbound_pckts"] = con4tuple.get_inbound_pckts()
                features["outbound_pckts"] = con4tuple.get_outbound_pckts()
                features["periodicity_average"] = con4tuple.get_periodicity_average()
                features["periodicity_standart_deviation"] = con4tuple.get_periodicity_standart_deviation()
                features["ssl_ratio"] = con4tuple.get_ssl_ratio()
                features["average_public_key"] = con4tuple.get_average_public_key()
                features["tls_version_ratio"] = con4tuple.get_tls_version_ratio()
                features["average_of_certificate_length"] = con4tuple.get_average_of_certificate_length()
                features["standart_deviation_cert_length"] = con4tuple.get_standart_deviation_cert_length()
                features["is_valid_certificate_during_capture"] = con4tuple.is_valid_certificate_during_capture()
                features["amount_diff_certificates"] = con4tuple.get_amount_diff_certificates()
                features["number_of_domains_in_certificate"] = con4tuple.get_number_of_domains_in_certificate()
                features["get_certificate_ratio"] = con4tuple.get_certificate_ratio()
                features["number_of_certificate_path"] = con4tuple.get_number_of_certificate_path()
                features["x509_ssl_ratio"] = con4tuple.x509_ssl_ratio()
                features["SNI_ssl_ratio"] = con4tuple.SNI_ssl_ratio()
                features["self_signed_ratio"] = con4tuple.self_signed_ratio()
                features["is_SNIs_in_SNA_dns"] = con4tuple.is_SNIs_in_SNA_dns()
                features["SNI_equal_DstIP"] = con4tuple.get_SNI_equal_DstIP()
                features["is_CNs_in_SNA_dns"] = con4tuple.is_CNs_in_SNA_dns()

                # New features
                features["ratio_of_differ_SNI_in_ssl_log"] = con4tuple.ratio_of_differ_SNI_in_ssl_log()
                features["ratio_of_differ_subject_in_ssl_log"] = con4tuple.ratio_of_differ_subject_in_ssl_log()
                features["ratio_of_differ_issuer_in_ssl_log"] = con4tuple.ratio_of_differ_issuer_in_ssl_log()
                features["ratio_of_differ_subject_in_cert"] = con4tuple.ratio_of_differ_subject_in_cert()
                features["ratio_of_differ_issuer_in_cert"] = con4tuple.ratio_of_differ_issuer_in_cert()
                features["ratio_of_differ_sandns_in_cert"] = con4tuple.ratio_of_differ_sandns_in_cert()
                features["ratio_of_same_subjects"] = con4tuple.ratio_of_same_subjects()
                features["ratio_of_same_issuer"] = con4tuple.ratio_of_same_issuer()
                features["ratio_is_same_CN_and_SNI"] = con4tuple.ratio_is_same_CN_and_SNI()
                features["average_certificate_exponent"] = con4tuple.average_certificate_exponent()
                features["is_SNI_in_top_level_domain"] = con4tuple.is_SNI_in_top_level_domain()
                features["ratio_certificate_path_error"] = con4tuple.ratio_certificate_path_error()
                features["ratio_missing_cert_in_cert_path"] = con4tuple.ratio_missing_cert_in_cert_path()

                features["label"] = con4tuple.get_label_of_connection()

                if line == 0:
                    writer = csv.DictWriter(csvfile, fieldnames=features.keys(), lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
                    writer.writeheader()

                writer.writerow(features)
                line += 1

    """
    def create_dataset(self):
        print "----------------------------------------"
        print "Creating data ..."

        space = '	'

        with open(c.model_folder + "/features.txt", 'w') as f:
            for key in self.connection_4_tuples.keys():
                fnames = "key" + "\n"
                line = str(key) + space
                fnames += "number_of_flows" + "\n"
                line += str(self.connection_4_tuples[key].get_number_of_flows()) + space
                fnames += "average_of_duration" + "\n"
                line += str(self.connection_4_tuples[key].get_average_of_duration()) + space
                fnames += "standard_deviation_duration" + "\n"
                line += str(self.connection_4_tuples[key].get_standard_deviation_duration()) + space
                fnames += "percent_of_standard_deviation_duration" + "\n"
                line += str(self.connection_4_tuples[key].get_percent_of_standard_deviation_duration()) + space
                fnames += "total_size_of_flows_orig" + "\n"
                line += str(self.connection_4_tuples[key].get_total_size_of_flows_orig()) + space
                fnames += "total_size_of_flows_resp" + "\n"
                line += str(self.connection_4_tuples[key].get_total_size_of_flows_resp()) + space
                fnames += "ratio_of_sizes" + "\n"
                line += str(self.connection_4_tuples[key].get_ratio_of_sizes()) + space
                fnames += "percent_of_established_states" + "\n"
                line += str(self.connection_4_tuples[key].get_percent_of_established_states()) + space
                fnames += "inbound_pckts" + "\n"
                line += str(self.connection_4_tuples[key].get_inbound_pckts()) + space
                fnames += "outbound_pckts" + "\n"
                line += str(self.connection_4_tuples[key].get_outbound_pckts()) + space
                fnames += "periodicity_average" + "\n"
                line += str(self.connection_4_tuples[key].get_periodicity_average()) + space
                fnames += "periodicity_standart_deviation" + "\n"
                line += str(self.connection_4_tuples[key].get_periodicity_standart_deviation()) + space
                fnames += "ssl_ratio" + "\n"
                line += str(self.connection_4_tuples[key].get_ssl_ratio()) + space
                fnames += "average_public_key" + "\n"
                line += str(self.connection_4_tuples[key].get_average_public_key()) + space
                fnames += "tls_version_ratio" + "\n"
                line += str(self.connection_4_tuples[key].get_tls_version_ratio()) + space
                fnames += "average_of_certificate_length" + "\n"
                line += str(self.connection_4_tuples[key].get_average_of_certificate_length()) + space
                fnames += "standart_deviation_cert_length" + "\n"
                line += str(self.connection_4_tuples[key].get_standart_deviation_cert_length()) + space
                fnames += "is_valid_certificate_during_capture" + "\n"
                line += str(self.connection_4_tuples[key].is_valid_certificate_during_capture()) + space
                fnames += "amount_diff_certificates" + "\n"
                line += str(self.connection_4_tuples[key].get_amount_diff_certificates()) + space
                fnames += "number_of_domains_in_certificate" + "\n"
                line += str(self.connection_4_tuples[key].get_number_of_domains_in_certificate()) + space
                fnames += "get_certificate_ratio" + "\n"
                line += str(self.connection_4_tuples[key].get_certificate_ratio()) + space
                fnames += "number_of_certificate_path" + "\n"
                line += str(self.connection_4_tuples[key].get_number_of_certificate_path()) + space
                fnames += "x509_ssl_ratio" + "\n"
                line += str(self.connection_4_tuples[key].x509_ssl_ratio()) + space
                fnames += "SNI_ssl_ratio" + "\n"
                line += str(self.connection_4_tuples[key].SNI_ssl_ratio()) + space
                fnames += "self_signed_ratio" + "\n"
                line += str(self.connection_4_tuples[key].self_signed_ratio()) + space
                fnames += "is_SNIs_in_SNA_dns" + "\n"
                line += str(self.connection_4_tuples[key].is_SNIs_in_SNA_dns()) + space
                fnames += "SNI_equal_DstIP" + "\n"
                line += str(self.connection_4_tuples[key].get_SNI_equal_DstIP()) + space
                fnames += "is_CNs_in_SNA_dns" + "\n"
                line += str(self.connection_4_tuples[key].is_CNs_in_SNA_dns()) + space

                # New features
                fnames += "ratio_of_differ_SNI_in_ssl_log" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_differ_SNI_in_ssl_log()) + space
                fnames += "ratio_of_differ_subject_in_ssl_log" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_differ_subject_in_ssl_log()) + space
                fnames += "ratio_of_differ_issuer_in_ssl_log" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_differ_issuer_in_ssl_log()) + space
                fnames += "ratio_of_differ_subject_in_cert" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_differ_subject_in_cert()) + space
                fnames += "ratio_of_differ_issuer_in_cert" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_differ_issuer_in_cert()) + space
                fnames += "ratio_of_differ_sandns_in_cert" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_differ_sandns_in_cert()) + space
                fnames += "ratio_of_same_subjects" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_same_subjects()) + space
                fnames += "ratio_of_same_issuer" + "\n"
                line += str(self.connection_4_tuples[key].ratio_of_same_issuer()) + space
                fnames += "ratio_is_same_CN_and_SNI" + "\n"
                line += str(self.connection_4_tuples[key].ratio_is_same_CN_and_SNI()) + space
                fnames += "average_certificate_exponent" + "\n"
                line += str(self.connection_4_tuples[key].average_certificate_exponent()) + space
                fnames += "is_SNI_in_top_level_domain" + "\n"
                line += str(self.connection_4_tuples[key].is_SNI_in_top_level_domain()) + space
                fnames += "ratio_certificate_path_error" + "\n"
                line += str(self.connection_4_tuples[key].ratio_certificate_path_error()) + space
                fnames += "ratio_missing_cert_in_cert_path" + "\n"
                line += str(self.connection_4_tuples[key].ratio_missing_cert_in_cert_path()) + space
                fnames += "label" + "\n"
                line += self.connection_4_tuples[key].get_label_of_connection()
                f.write(line + "\n")

        with open(c.model_folder + "/features_name.txt", 'w') as n:
            n.write(fnames)
    """

    def save_dataset_information(self):
        print "----------------------------------------"
        print "Saving data ..."
        space = '	'
        # with open("ExtractedData\\" + "conn_result.txt", 'w') as f:
        with open("../Models/dataset_info.txt", 'w') as f:
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
        with open(c.model_folder + '/malware_certificates', 'w') as f:
            for line in x509_lines:
                f.write(line + "\n")
            f.close()
