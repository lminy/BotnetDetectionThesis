import csv
import config as c

import pandas as pd
import numpy as np
import matplotlib
from collections import Counter
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt

graphs_folder = "./graphs/"

df = pd.read_csv(c.model_folder + 'features.csv')


names = ["in_alexa_top100","in_alexa_top1k","in_alexa_top10k","in_alexa_top100k","in_alexa_top1m","not_in_alexa",
         "FQDN_length","domain_name_length","number_of_numerical_chars","number_of_non_alphanumeric_chars",
         "number_unique_IP_addresses_in_response","number_of_subdomains","average_ttls","min_ttls",
         "max_ttls","number_of_hyphens_in_fqdn","length_of_longest_subdomain_name","number_of_voyels_in_fqdn",
         "number_of_different_chars_in_fqdn","number_of_consonants_in_fqdn",
         "shannon_entropy_2ld","shannon_entropy_3ld","label"]

#print(type(normal.values))
#print v.ndim

#df.plot(kind='bar', stacked=True);

"""
shannon_entropy_2ld_botnet = list()
shannon_entropy_2ld_normal = list()

with open(c.model_folder + 'features.csv') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        print row['key'], row['number_of_flows']
        if row['label'] == 'MALWARE':
            shannon_entropy_2ld_botnet.append(float(row['shannon_entropy_2ld']))
        else:
            shannon_entropy_2ld_normal.append(float(row['shannon_entropy_2ld']))

"""

import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt


def compute_stat_continue(feature_name, data):
    fig, ax = plt.subplots()
    ax.set_title('Feature ' + feature_name)
    ax.boxplot(data)

    fig.savefig(graphs_folder + feature_name + '.png')


features_continue = ["FQDN_length","domain_name_length","number_of_numerical_chars","number_of_non_alphanumeric_chars",
         "number_unique_IP_addresses_in_response","number_of_subdomains","average_ttls","min_ttls",
         "max_ttls","number_of_hyphens_in_fqdn","length_of_longest_subdomain_name","number_of_voyels_in_fqdn",
         "number_of_different_chars_in_fqdn","number_of_consonants_in_fqdn",
         "shannon_entropy_2ld","shannon_entropy_3ld"]

def plot_all_stat_continue():
    for feature_name in features_continue:
        normal = df.loc[df['label'] == 'NORMAL'][feature_name]
        malware = df.loc[df['label'] == 'MALWARE'][feature_name]
        data = [normal, malware]
        compute_stat_continue(feature_name, data)

def plot_alexa():
    # Example https://matplotlib.org/2.0.2/examples/api/barchart_demo.html

    features_alexa = ["in_alexa_top100", "in_alexa_top1k", "in_alexa_top10k", "in_alexa_top100k", "in_alexa_top1m",
                      "not_in_alexa"]
    features_names_siplified = ["top 100", "top 1k", "top 10k", "top 100k", " top 1m", "not"]

    normal_means = list()
    normal_std = list()

    malware_means = list()
    malware_std = list()
    for i in range(len(features_alexa)):
        normal = df.loc[df['label'] == 'NORMAL'][features_alexa[i]]
        malware = df.loc[df['label'] == 'MALWARE'][features_alexa[i]]
        normal_means.append(np.mean(normal))
        normal_std.append(np.std(normal))
        malware_means.append(np.mean(malware))
        malware_std.append(np.std(malware))



    N = len(features_alexa)
    men_means = (20, 35, 30, 35, 27)
    men_std = (2, 3, 4, 1, 2)

    ind = np.arange(N)  # the x locations for the groups
    width = 0.35       # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(ind, normal_means, width, color='g', yerr=normal_std)

    women_means = (25, 32, 34, 20, 25)
    women_std = (3, 5, 2, 3, 3)
    rects2 = ax.bar(ind + width, malware_means, width, color='r', yerr=malware_std)

    # add some text for labels, title and axes ticks
    ax.set_ylabel('Scores')
    ax.set_title('Scores by group and gender')
    ax.set_xticks(ind + width / 2)
    ax.set_xticklabels(features_names_siplified)

    ax.legend((rects1[0], rects2[0]), ('Normal', 'Malware'))
    fig.savefig(graphs_folder + "features_alexa" + '.png')

def plot_alexa2():
    # Example https://matplotlib.org/2.0.2/examples/api/barchart_demo.html

    features_alexa = ["in_alexa_top100", "in_alexa_top1k", "in_alexa_top10k", "in_alexa_top100k", "in_alexa_top1m",
                      "not_in_alexa"]
    features_names_simplified = ["top 100", "top 1k", "top 10k", "top 100k", " top 1m", "not"]

    normal_percentage = list()
    malware_percentage = list()
    for i in range(len(features_alexa)):
        normal = df.loc[df['label'] == 'NORMAL'][features_alexa[i]]
        malware = df.loc[df['label'] == 'MALWARE'][features_alexa[i]]
        normal_percentage.append(sum(normal) / float(len(df)))
        malware_percentage.append(sum(malware) / float(len(df)))

    N = len(features_alexa)

    ind = np.arange(N)  # the x locations for the groups
    width = 0.35       # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(ind, normal_percentage, width, color='g')

    rects2 = ax.bar(ind + width, malware_percentage, width, color='r')

    # add some text for labels, title and axes ticks
    ax.set_ylabel('Percentage of connection 4 tuples')
    ax.set_title('Connection 4 tuples in Top alexa')
    ax.set_xticks(ind + width / 2)
    ax.set_xticklabels(features_names_simplified)

    ax.legend((rects1[0], rects2[0]), ('Normal', 'Malware'))
    fig.savefig(graphs_folder + "features_alexa2" + '.png')


def plot_barchar(features_name):
    # Example https://matplotlib.org/2.0.2/examples/api/barchart_demo.html

    normal = df.loc[df['label'] == 'NORMAL'][features_name]
    malware = df.loc[df['label'] == 'MALWARE'][features_name]
    c = Counter(normal)
    print c.most_common(15)
    return



    features_alexa = ["in_alexa_top100", "in_alexa_top1k", "in_alexa_top10k", "in_alexa_top100k", "in_alexa_top1m",
                      "not_in_alexa"]
    features_names_simplified = ["top 100", "top 1k", "top 10k", "top 100k", " top 1m", "not"]

    normal_means = list()
    normal_std = list()

    malware_means = list()
    malware_std = list()
    for i in range(len(features_alexa)):
        normal = df.loc[df['label'] == 'NORMAL'][features_alexa[i]]
        malware = df.loc[df['label'] == 'MALWARE'][features_alexa[i]]
        normal_means.append(np.mean(normal))
        normal_std.append(np.std(normal))
        malware_means.append(np.mean(malware))
        malware_std.append(np.std(malware))



    N = len(features_alexa)
    men_means = (20, 35, 30, 35, 27)
    men_std = (2, 3, 4, 1, 2)

    ind = np.arange(N)  # the x locations for the groups
    width = 0.35       # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(ind, normal_means, width, color='g', yerr=normal_std)

    women_means = (25, 32, 34, 20, 25)
    women_std = (3, 5, 2, 3, 3)
    rects2 = ax.bar(ind + width, malware_means, width, color='r', yerr=malware_std)

    # add some text for labels, title and axes ticks
    ax.set_ylabel('Scores')
    ax.set_title('Scores by group and gender')
    ax.set_xticks(ind + width / 2)
    ax.set_xticklabels(features_names_simplified)

    ax.legend((rects1[0], rects2[0]), ('Normal', 'Malware'))
    fig.savefig(graphs_folder + "features_alexa" + '.png')

#plot_all_stat_continue()
#plot_alexa2()
#plot_barchar("number_unique_IP_addresses_in_response")

nb_conn_tuples_normal = len(df.loc[df['label'] == 'NORMAL'])
nb_conn_tuples_malware = len(df.loc[df['label'] == 'MALWARE'])
print "Number of conn4tuples Normal : " + str(nb_conn_tuples_normal)
print "Number of conn4tuples Malware : " + str(nb_conn_tuples_malware)
print "Total : " + str(nb_conn_tuples_normal + nb_conn_tuples_malware)
