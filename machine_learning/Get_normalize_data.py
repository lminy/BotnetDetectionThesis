
import csv
import config as c
import numpy as np

featuresname_all = [
    "number_of_flows",
    "average_of_duration",
    "standard_deviation_duration",
    "percent_of_standard_deviation_duration",
    "total_size_of_flows_orig",
    "total_size_of_flows_resp",
    "ratio_of_sizes",
    "percent_of_established_states",
    "inbound_pckts",
    "outbound_pckts",
    "periodicity_average",
    "periodicity_standart_deviation",
    "ssl_ratio",
    "average_public_key",
    "tls_version_ratio",
    "average_of_certificate_length",
    "standart_deviation_cert_length",
    "is_valid_certificate_during_capture",
    "amount_diff_certificates",
    "number_of_domains_in_certificate",
    "get_certificate_ratio",
    "number_of_certificate_path",
    "x509_ssl_ratio",
    "SNI_ssl_ratio",
    "self_signed_ratio",
    "is_SNIs_in_SNA_dns",
    "SNI_equal_DstIP",
    "is_CNs_in_SNA_dns",
    "ratio_of_differ_SNI_in_ssl_log",
    "ratio_of_differ_subject_in_ssl_log",
    "ratio_of_differ_issuer_in_ssl_log",
    "ratio_of_differ_subject_in_cert",
    "ratio_of_differ_issuer_in_cert",
    "ratio_of_differ_sandns_in_cert",
    "ratio_of_same_subjects",
    "ratio_of_same_issuer",
    "ratio_is_same_CN_and_SNI",
    "average_certificate_exponent",
    "is_SNI_in_top_level_domain",
    "ratio_certificate_path_error",
    "ratio_missing_cert_in_cert_path",
    "in_alexa_top100",
    "in_alexa_top1k",
    "in_alexa_top10k",
    "in_alexa_top100k",
    "in_alexa_top1m",
    "not_in_alexa",
    "FQDN_length",
    "domain_name_length",
    "number_of_numerical_chars",
    "number_of_non_alphanumeric_chars",
    "number_unique_IP_addresses_in_response",
    "number_of_subdomains",
    "average_ttls",
    "std_ttls",
    "min_ttls",
    "max_ttls",
    "number_of_hyphens_in_fqdn",
    "length_of_longest_subdomain_name",
    "number_of_voyels_in_fqdn",
    "number_of_different_chars_in_fqdn",
    "number_of_consonants_in_fqdn",
    "shannon_entropy_2ld",
    "shannon_entropy_3ld"]

less_important_features = [
    "SNI_equal_DstIP",
    "ratio_of_differ_issuer_in_cert",
    "ratio_certificate_path_error",
    "ratio_missing_cert_in_cert_path",
    "standart_deviation_cert_length",
    "ratio_of_differ_subject_in_cert",
    "percent_of_established_states",
    "ratio_of_differ_issuer_in_ssl_log",
    "ratio_of_differ_subject_in_ssl_log",
    "is_SNI_in_top_level_domain",

    "ratio_of_same_issuer",
    "ratio_of_differ_sandns_in_cert",
    "in_alexa_top100k",
    "tls_version_ratio",
    "is_SNIs_in_SNA_dns",
    "in_alexa_top10k",
    "average_public_key",
    "number_of_hyphens_in_fqdn",
    "ratio_of_same_subjects",
    "average_certificate_exponent",

    "in_alexa_top1k",
    "is_CNs_in_SNA_dns",
    "amount_diff_certificates",
    "number_of_voyels_in_fqdn",
    "ssl_ratio",
    "in_alexa_top1m",
    "in_alexa_top100",
    "number_of_non_alphanumeric_chars",
    "x509_ssl_ratio",
    "number_of_flows",

    "periodicity_standart_deviation",
    "SNI_ssl_ratio",
    "length_of_longest_subdomain_name",
    "FQDN_length",
    "number_of_domains_in_certificate",
    "number_of_different_chars_in_fqdn",
    "percent_of_standard_deviation_duration",
    "domain_name_length",
    "ratio_is_same_CN_and_SNI",
    "number_of_certificate_path"
]

features_set = {
    "all": featuresname_all,
    "dns": featuresname_all[41:],
    "https": featuresname_all[:41],
    "reduced": filter(lambda f: f not in less_important_features[:20], featuresname_all),
    "reduced_30": filter(lambda f: f not in less_important_features[:30], featuresname_all),
    "reduced_40": filter(lambda f: f not in less_important_features[:40], featuresname_all)
}


def read_features(filename, set_name):
    import pandas as pd
    X = pd.read_csv(filename)
    return X[features_set[set_name]]


def read_labels(filename):
    with open(filename, 'r') as csvfile:
        csvreader = csv.reader(csvfile, lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        y = csvreader.next()
    return y


def get_all_data(models_folder, set_name="all"):
    X_train = read_features(models_folder + "X_train.csv", set_name)
    X_test = read_features(models_folder + "X_test.csv", set_name)
    y_train = read_labels(models_folder + "y_train.csv")
    y_test = read_labels(models_folder + "y_test.csv")
    #return np.array(X_train), np.array(X_test), np.array(y_train), np.array(y_test)
    return X_train, X_test, y_train, y_test