# 0     connection key

# 1	    get_number_of_flows()
# 2	    get_average_of_duration()
# 3	    get_standard_deviation_duration()
# 4	    get_percent_of_standard_deviation_duration()
# 5	    get_total_size_of_flows_orig()
# 6	    get_total_size_of_flows_resp()
# 7	    get_ratio_of_sizes()
# 8	    get_percent_of_established_states()
# 9	    get_inbound_pckts()
# 10	get_outbound_pckts()
# 11	get_periodicity_average()
# 12	get_periodicity_standart_deviation()
# 13	get_ssl_ratio()
# 14	get_average_public_key()
# 15	get_tls_version_ratio()
# 16	get_average_of_certificate_length()
# 17	get_standart_deviation_cert_length()
# 18	is_valid_certificate_during_capture()
# 19	get_amount_diff_certificates()
# 20	get_number_of_domains_in_certificate()
# 21	get_certificate_ratio()
# 22	get_number_of_certificate_path()
# 23	x509_ssl_ratio()
# 24	SNI_ssl_ratio()
# 25	self_signed_ratio()
# 26	is_SNIs_in_SNA_dns()
# 27	get_SNI_equal_DstIP()
# 28    is_CNs_in_SNA_dns()

# 29    LABEL


import sys

space = '	'

path_to_conn_result = sys.argv[1]
print path_to_conn_result

"""
Read ConnRes
"""
normal_count = 0
normal_is_valid_cert = 0

malware_count = 0
malware_is_valid_cert = 0
with open(path_to_conn_result) as f:
    for line in f:
        print line

        split = line.split('	')
        label = split[42]


        feature = int(split[18])

        if 'NORMAL' in label:
            normal_is_valid_cert += feature
            normal_count += 1
        if 'MALWARE' in label:
            malware_is_valid_cert += feature
            malware_count += 1

f.close()

print "All normal:", normal_count
print "is not valid", normal_is_valid_cert

print "All malwares:", malware_count
print "is not valid", malware_is_valid_cert