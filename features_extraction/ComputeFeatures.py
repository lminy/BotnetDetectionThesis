from datetime import datetime
from ExtractFeatures import ExtractFeatures
import config as c

from logger import get_logger
logger = get_logger("debug")

class ComputeFeatures(ExtractFeatures):

    def __init__(self):
        super(ComputeFeatures, self).__init__()
        self.file_time_name = str(datetime.strftime(datetime.utcnow(), "%Y-%m-%d_%H-%M"))

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

    def create_balanced_dataset(self):
        import csv
        from collections import OrderedDict

        botnet_lines = list()
        normal_lines = list()

        for key, con4tuple in self.connection_4_tuples.iteritems():
            dest_ip = key[1]
            if dest_ip not in self.dns_connections_index:
                print dest_ip + "NOT FOUND IN DNS RECORDS..."
            else:
                dns_conn = self.dns_connections_index[dest_ip]

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

                # DNS Features
                features.update(benchmark(dns_conn.compute_alexa_features))
                features["FQDN_length"] = benchmark(dns_conn.get_FQDN_length)
                features["domain_name_length"] = benchmark(dns_conn.get_domain_name_length)
                features["number_of_numerical_chars"] = benchmark(dns_conn.get_number_of_numerical_chars)
                features["number_of_non_alphanumeric_chars"] = benchmark(
                    dns_conn.get_number_of_non_alphanumeric_chars)
                features["number_unique_IP_addresses_in_response"] = benchmark(
                    dns_conn.get_number_unique_IP_addresses_in_response)
                features["number_of_subdomains"] = benchmark(dns_conn.get_number_of_subdomains)
                features["average_ttls"] = benchmark(dns_conn.get_average_ttls)
                features["min_ttls"] = benchmark(dns_conn.get_min_ttls)
                features["max_ttls"] = benchmark(dns_conn.get_max_ttls)
                features["number_of_hyphens_in_fqdn"] = benchmark(dns_conn.get_number_of_hyphens_in_fqdn)
                features["length_of_longest_subdomain_name"] = benchmark(
                    dns_conn.get_length_of_longest_subdomain_name)
                features["number_of_voyels_in_fqdn"] = benchmark(dns_conn.get_number_of_voyels_in_fqdn)
                features["number_of_different_chars_in_fqdn"] = benchmark(
                    dns_conn.get_number_of_different_chars_in_fqdn)
                features["number_of_consonants_in_fqdn"] = benchmark(dns_conn.get_number_of_consonants_in_fqdn)
                features["shannon_entropy_2ld"] = benchmark(dns_conn.get_shannon_entropy_2ld)
                features["shannon_entropy_3ld"] = benchmark(dns_conn.get_shannon_entropy_3ld)

                features["label"] = con4tuple.get_label_of_connection()

                if con4tuple.is_malware():
                    botnet_lines.append(features)
                else:
                    normal_lines.append(features)

        # Shuffle & balance the whole dataset (50-50 botnet/normal traffic)\n
        from sklearn.utils import shuffle

        max_sample = min(len(botnet_lines), len(normal_lines))

        logger.info("Number of Conn3tuples (botnet, normal) : {}".format((len(botnet_lines),len(normal_lines))))
        logger.info("Down-sampling to {} conn4tuples/class".format(max_sample))

        lines = shuffle(botnet_lines, n_samples=max_sample) + shuffle(normal_lines, n_samples=max_sample)
        logger.info("Total dataset lines: {}".format(len(lines)))

        with open(c.model_folder + 'features.csv', 'wb') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=features.keys(), lineterminator='\n', delimiter=',',
                                    quoting=csv.QUOTE_NONNUMERIC)
            writer.writeheader()
            writer.writerows(lines)

    def create_dataset_dns(self):
        import csv
        from collections import OrderedDict

        with open(c.model_folder + 'dns_features.csv', 'wb') as csvfile:
            line = 0

            for key, dns_conn in self.dns_connections.iteritems():
                features = OrderedDict()
                features["key"] = key
                features.update(benchmark(dns_conn.compute_alexa_features))
                features["FQDN_length"] = benchmark(dns_conn.get_FQDN_length)
                features["domain_name_length"] = benchmark(dns_conn.get_domain_name_length)
                features["number_of_numerical_chars"] = benchmark(dns_conn.get_number_of_numerical_chars)
                features["number_of_non_alphanumeric_chars"] = benchmark(dns_conn.get_number_of_non_alphanumeric_chars)
                features["number_unique_IP_addresses_in_response"] = benchmark(
                    dns_conn.get_number_unique_IP_addresses_in_response)
                features["number_of_subdomains"] = benchmark(dns_conn.get_number_of_subdomains)
                features["average_ttls"] = benchmark(dns_conn.get_average_ttls)
                features["min_ttls"] = benchmark(dns_conn.get_min_ttls)
                features["max_ttls"] = benchmark(dns_conn.get_max_ttls)
                features["number_of_hyphens_in_fqdn"] = benchmark(dns_conn.get_number_of_hyphens_in_fqdn)
                features["length_of_longest_subdomain_name"] = benchmark(dns_conn.get_length_of_longest_subdomain_name)
                features["number_of_voyels_in_fqdn"] = benchmark(dns_conn.get_number_of_voyels_in_fqdn)
                features["number_of_different_chars_in_fqdn"] = benchmark(
                    dns_conn.get_number_of_different_chars_in_fqdn)
                features["number_of_consonants_in_fqdn"] = benchmark(dns_conn.get_number_of_consonants_in_fqdn)
                features["shannon_entropy_2ld"] = benchmark(dns_conn.get_shannon_entropy_2ld)
                features["shannon_entropy_3ld"] = benchmark(dns_conn.get_shannon_entropy_3ld)

                if line == 0:
                    writer = csv.DictWriter(csvfile, fieldnames=features.keys(), lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
                    writer.writeheader()

                writer.writerow(features)
                line += 1

    def save_dataset_information(self):
        space = '	'
        # with open("ExtractedData\\" + "conn_result.txt", 'w') as f:
        with open(c.model_folder + "/dataset_info.txt", 'w') as f:
            for key in self.dataset_information_dict.keys():
                f.write(str(key) + space +
                        str(self.dataset_information_dict[key].ssl_lines) + space +
                        str(self.dataset_information_dict[key].not_founded_x509_lines) + space +
                        str(self.dataset_information_dict[key].founded_x509_lines) + space +
                        str(self.dataset_information_dict[key].err_not_added_x509) +
                        "\n")
        f.close()


    """
    Statistic methods.
    """
    def print_statistic(self):
        logger.info("-------------------------------------------")
        logger.info("----------- Statistic ---------------------")
        logger.info("-------------------------------------------")
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
                logger.error("Error: More labels in one 4-tuples")
                # Same amout of labels in one 4-tuple?
                if conn_tuple.get_malware_label() == conn_tuple.get_normal_label():
                    logger.warning("Watch out: same amount of labels")
                    logger.warning("Normal: {}".format(conn_tuple.get_normal_label()))
                    logger.warning("Malware: {}".format(conn_tuple.get_malware_label()))

            if conn_tuple.is_malware():
                malware_tuples += 1
                flows_malware += conn_tuple.get_number_of_ssl_flows()
                cert_malware += len(conn_tuple.get_certificate_serial_dict().keys())

                malware_certificates_array += conn_tuple.get_x509_list()
            else:
                normal_tuples += 1
                flows_normal += conn_tuple.get_number_of_ssl_flows()
                cert_normal += len(conn_tuple.get_certificate_serial_dict().keys())

        logger.info("Connection 4-tuples:")
        logger.info("All 4_tuples: {}".format(len(self.connection_4_tuples.keys())))
        logger.info("Normal 4-tuples: {}".format(normal_tuples))
        logger.info("Malware 4-tuples: {}".format(malware_tuples))

        logger.info("Flows")
        logger.info("All gathered flows: {}".format(flows_together))
        logger.info("Normal flows: {}".format(flows_normal))
        logger.info("Malware flows: {}".format(flows_malware))

        logger.info("Certificates")
        logger.info("All gathered certificates: {}".format(cert_together))
        logger.info("Normal certificates: {}".format(cert_normal))
        logger.info("Malware certificates: {}".format(cert_malware))

        # Save malware certificates.
        self.save_malware_certificates(malware_certificates_array)

    def save_malware_certificates(self, x509_lines):
        with open(c.model_folder + '/malware_certificates', 'w') as f:
            for line in x509_lines:
                f.write(line + "\n")
            f.close()

def benchmark(func, *params):
    #import datetime
    #import time
    #start_time = time.time()
    return_value = func(*params) if params else func()
    #total_time = datetime.timedelta(seconds=time.time() - start_time)
    #print("Function " + func.__name__ + " - execution time : " + str(total_time))#.strftime('%H:%M:%S'))
    return return_value