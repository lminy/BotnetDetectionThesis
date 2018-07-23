import os
import config as c


def check_conn_label(dataset_path):
    print "<< Labeling " + dataset_path
    flow_array = []
    space = '	'
    normal_label = 0
    with open(dataset_path + '/bro/conn.log', 'r') as f:
        for line in f:
            newline = line
            if not ('#' == line[0]):
                newline = line.rstrip() + space + "From-Normal" + "\n"
                normal_label += 1
            else:
                if 'fields' in line:
                    newline = line.rstrip() + space + "label" + "\n"
                elif 'types' in line:
                    newline = line.rstrip() + space + "string" + "\n"

            flow_array.append(newline)

    print "normals:", normal_label
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
    for sub_set in os.listdir(c.datasets_folder):
        if not sub_set.startswith(".") and sub_set.startswith("CTU-Normal"):
            flow_array = check_conn_label(c.datasets_folder + sub_set)
            write_conn(c.datasets_folder + sub_set, flow_array)
