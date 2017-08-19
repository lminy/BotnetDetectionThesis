from ExtractFeatures import ExtractFeatures


class ComputeFeatures(ExtractFeatures):

    def __init__(self):
        super(ComputeFeatures, self).__init__()

    def create_dataset(self):
        print "----------------------------------------"
        print "Creatind data ..."
        useful_ssl_flows = 0
        all_flows = 0
        space = '	'
        # with open("ExtractedData\\" + "conn_result.txt", 'w') as f:
        with open("/home/frenky/PycharmProjects/HTTPSDetector/FeatureExtraction/ExtractedData/" + "conn_result_2017_08_16_1.txt", 'w') as f:
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

                        self.connection_4_tuples[key].get_label_of_connection() +
                        "\n")
                useful_ssl_flows += self.connection_4_tuples[key].get_number_of_ssl_flows()
                all_flows += self.connection_4_tuples[key].get_number_of_flows()

        f.close()


    def save_dataset_information(self, dataset_info_dict):
        print "----------------------------------------"
        print "Saving data ..."
        space = '	'
        # with open("ExtractedData\\" + "conn_result.txt", 'w') as f:
        with open("/home/frenky/PycharmProjects/HTTPSDetector/FeatureExtraction/ExtractedData/" + "dataset_info_2017_08_16.txt", 'w') as f:
            for key in dataset_info_dict.keys():
                f.write(str(key) + space +
                        str(dataset_info_dict[key].ssl_lines) + space +
                        str(dataset_info_dict[key].not_founded_x509_lines) + space +
                        str(dataset_info_dict[key].founded_x509_lines) + space +
                        str(dataset_info_dict[key].err_not_added_x509) +

                        "\n")
        f.close()

    """
    Statistic methods.
    """
    def print_statistic(self):
        print "-------------------------------------------"
        print "----------- Statistic ---------------------"
        print "-------------------------------------------"
        normal_tuples = 0
        malware_tuples = 0
        flows_together = 0
        flows_normal = 0
        flows_malware = 0
        for tuple_key in self.connection_4_tuples.keys():
            conn_tuple = self.connection_4_tuples[tuple_key]
            flows_together += conn_tuple.get_number_of_ssl_flows()
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
            else:
                normal_tuples += 1
                flows_normal += conn_tuple.get_number_of_ssl_flows()

        print "Connection 4-tuples:"
        print "Number of all 4_tuples:", len(self.connection_4_tuples.keys())
        print "Number of normal 4-tuples:", normal_tuples
        print "Number of malware 4-tuples:", malware_tuples
        print "Flows"
        print "All gathered flows:", flows_together
        print "Normal flows:", flows_normal
        print "Malware flows:", flows_malware