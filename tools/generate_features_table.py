import config as c
import csv
from collections import OrderedDict


def get_features_name():
    with open(c.model_folder + "features.csv", 'r') as csvfile:
        csvreader = csv.reader(csvfile, lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        features_name = csvreader.next()[1:-1]
        return features_name

if __name__ == '__main__':

    features_name = get_features_name()

    #latex_table = "\\begin{table}[!h]\n" \
    #              "\centering\n" \
    #              "\\begin{adjustbox}{max width=\\textwidth}\n" \
    #              "\\begin{tabular}{llll}\n"
    headers = "\\textbf{{{}}} & \\textbf{{{}}} & \\textbf{{{}}} & \\textbf{{{}}} \\\\ \n\hline \n".format("", "ID", "Feature name", "proposed in")
    # latex_table += headers

    # Long table
    latex_table = "\\begin{longtable}{llll}\n"
    latex_table += headers
    latex_table += "\endhead\n" \
                   "\endfoot\n" \

    dns_features_name = features_name[41:]
    ordered_dns = OrderedDict().fromkeys(dns_features_name)
    dns_features_references = {
        'number_of_different_chars_in_fqdn': "marques2017thesis",
         'number_of_hyphens_in_fqdn': "wang2015breakingbad",
         'shannon_entropy_3ld': "marques2017thesis",
         'number_of_voyels_in_fqdn': "aashna2017dga",
         'in_alexa_top100': "anderson2016identifying",
         'number_of_subdomains': "hao2017exploring",
         'not_in_alexa': "anderson2016identifying",
         'min_ttls': "marques2017thesis",
         'shannon_entropy_2ld': "marques2017thesis",
         'length_of_longest_subdomain_name': "hao2017exploring",
         'in_alexa_top1m': "anderson2016identifying",
         'in_alexa_top1k': "anderson2016identifying",
         'in_alexa_top100k': "anderson2016identifying",
         'average_ttls': None,
         'in_alexa_top10k': "anderson2016identifying",
         'number_of_numerical_chars': "wang2015breakingbad,marques2017thesis,anderson2016identifying",
         'number_unique_IP_addresses_in_response': "marques2017thesis,anderson2016identifying",
         'std_ttls': None,
         'max_ttls': "marques2017thesis",
         'number_of_non_alphanumeric_chars': "anderson2016identifying",
         'FQDN_length': "hao2017exploring,aashna2017dga,anderson2016identifying",
         'number_of_consonants_in_fqdn': "aashna2017dga,marques2017thesis",
         'domain_name_length': "wang2015breakingbad,marques2017thesis,anderson2016identifying"}
    ordered_dns.update(dns_features_references)
    #for i, feature in enumerate(dns_features_name):
    #    latex_table += "{} & F{} & {} & {} \\\\ \n".format("",i,feature.replace("_", " "),"")

    i = 41
    for f, papers in ordered_dns.iteritems():
        latex_table += "{} & F{} & {} & {} \\\\ \n".format("",i,f.replace("_", " "),"" if papers is None else "\\cite{" + papers + "}")
        i += 1

    #latex_table += "\end{tabular}\n" \
    #               "\end{adjustbox}\n" \
    #               "\caption{DNS Features}\n" \
    #               "\label{table:dns_features}\n" \
    #               "\end{table}\n"
    # Long table
    latex_table += "\caption{DNS Features}\label{table:dns_features}\\\\ \n" \
                   "\end{longtable}"


    print latex_table


