"""
This script return all source ips in one dataset
"""
import os


def label_conn(path_to_conn_log, ips_dict):
    space = '	'
    with open(path_to_conn_log) as f:
        for line in f:
            newline = line
            if not ('#' == line[0]):
                split = line.split('	')
                src_address = split[2]

                try:
                    ips_dict[src_address] += 1
                except:
                    ips_dict[src_address] = 1

    f.close()


def get_all_conn_logs(path_to_bro):
    conn_file_list = []
    for log in os.listdir(path_to_bro):
        if log.endswith('.log') and 'conn.' in log:
            conn_file_list.append(log)
    return conn_file_list


def main():

    # Go through all dataset and label conn logs.
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_2_malware/no_proxy/'
    dir_n = 1
    for dir in os.listdir(dataset_path):
        print "--------------------------------------------------------"
        print "-------- #" + str(dir_n) + " " + dir
        print "--------------------------------------------------------"
        dir_n += 1

        bro_path = dataset_path + dir + '/bro/'
        conn_list = get_all_conn_logs(bro_path)
        ips_dict = dict()
        for conn_file in conn_list:
            label_conn(bro_path + conn_file, ips_dict)
        print ips_dict
        print 'number of ip address:', len(ips_dict.keys())


if __name__ == '__main__':
    main()
