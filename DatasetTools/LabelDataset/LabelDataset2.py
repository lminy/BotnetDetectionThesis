"""
Create labeled conn_label.log from conn.log by 'NormalIPs.txt'.
"""

import os

def load_ips():
    ips_list = []
    with open('./NormalIPs') as f:
        for line in f:
            if line[0] == '#':
                continue
            ips_list.append(line.rstrip())
    f.close()
    return ips_list


def write_conn(path,  flow_array):
    print "<< Writing new flows to conn_label.log."
    index = 0
    with open(path, 'w') as f:
        for i in range(len(flow_array)):
            f.write(flow_array[i])
            index += 1
    f.close()
    print "     << Number of lines:", index


def label_conn(path_to_conn_log, normal_ips_list, malware_ips_list):


    malware_label = 0
    normal_label = 0

    flow_array = []
    space = '	'
    with open(path_to_conn_log) as f:
        for line in f:
            newline = line
            if not ('#' == line[0]):
                split = line.split('	')
                src_address = split[2]

                label_state = 0
                if src_address in malware_ips_list:
                    newline = line.rstrip() + space + "From-Botnet" + "\n"
                    label_state += 1
                    malware_label += 1

                if src_address in normal_ips_list:
                    newline = line.rstrip() + space + "From-Normal" + "\n"
                    label_state += 1
                    normal_label += 1

                if label_state == 0:
                    newline = line.rstrip() + space + "Background" + "\n"

                if label_state > 1:
                    print "Error: SrcAddress has more classes. Program is terminated."
                    break
            else:
                if 'fields' in line:
                    newline = line.rstrip() + space + "label" + "\n"
                elif 'types' in line:
                    newline = line.rstrip() + space + "string" + "\n"

            flow_array.append(newline)
    f.close()
    print "<< We have read:"
    print "     Malware lines: ", malware_label
    print "     Normal lines: ", normal_label

    return flow_array


def get_all_conn_logs(path_to_bro):
    conn_file_list = []
    for log in os.listdir(path_to_bro):
        if log.endswith('.log') and 'conn.' in log:
            conn_file_list.append(log)
    return conn_file_list


def main():
    # Read ips from local file.
    normal_ips_list = load_ips()

    # Go through all dataset and label conn logs.
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_2_normal/unpack_logs/'
    dir_n = 0
    for dir in os.listdir(dataset_path):
        print "#" + str(dir_n) + " " + dir
        dir_n += 1

        bro_path = dataset_path + dir + '/bro/'
        conn_list = get_all_conn_logs(bro_path)
        for conn_file in conn_list:
            conn_contain = label_conn(bro_path + conn_file, normal_ips_list, malware_ips_list=[])

            new_conn_name = bro_path + conn_file.replace('.log', '') + '_label.log'
            write_conn(new_conn_name, conn_contain)


if __name__ == '__main__':
    main()
