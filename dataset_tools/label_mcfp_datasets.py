import os
import config as c
import json

def check_conn_label(dataset_path, normal_ips, infected_ips):
    print "<< Labeling " + dataset_path
    flow_array = []
    space = '\t'
    normal_label = 0
    malware_label = 0
    with open(dataset_path + '/bro/conn.log', 'r') as f:
        for line in f:
            newline = line

            if line[0] != '#':
                split = line.split('\t')
                src_address = split[2]

                if src_address in normal_ips:
                    newline = line.rstrip() + space + "From-Normal" + "\n"
                    normal_label += 1
                elif src_address in infected_ips:
                    newline = line.rstrip() + space + "From-Botnet" + "\n"
                    malware_label += 1
            else:
                if 'fields' in line:
                    newline = line.rstrip() + space + "label" + "\n"
                elif 'types' in line:
                    newline = line.rstrip() + space + "string" + "\n"

            flow_array.append(newline)

            if "#close" in line:
                break

    print "normals:", normal_label
    print "malwares:", malware_label
    print "     << End Labeling " + dataset_path
    return flow_array

def write_conn(path, flow_array):
    print "<< Writing new flows to " + path
    index = 0
    with open(path + '/bro/conn_label.log', 'w') as f:
        for i in range(len(flow_array)):
            f.write(flow_array[i])
            index += 1
    print "     << Number of lines:", index
    print "<< New file conn_label.log was succesfly created."

if __name__ == '__main__':

    with open('./infected_ips.json', 'r') as f:
        infected_ips = json.load(f)

    with open('./normal_ips.json', 'r') as f:
        normal_ips = json.load(f)

    for sub_set in os.listdir(c.datasets_folder_general):
        if sub_set.startswith("CTU-Malware-Capture-Botnet-") :
            dataset_number = int(sub_set.split('-')[4])
            if (dataset_number <= 42 or dataset_number >= 54) \
                    and (sub_set in infected_ips or sub_set in normal_ips):
                flow_array = check_conn_label(c.datasets_folder_general + sub_set, normal_ips[sub_set], infected_ips[sub_set])
                write_conn(c.datasets_folder_general + sub_set, flow_array)
