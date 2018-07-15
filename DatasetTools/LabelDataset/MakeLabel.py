"""
Usage:
python MakeLabel.py c:\Users\frenk\Documents\Skola\Bachelor_thesis\datasets\Experiment_1
"""
import sys
import glob


# This method returns path with name of the binetflow file.
def find_name_of_binetflow(path_to_folder):
    binetflow_files = glob.glob(path_to_folder + "/*.binetflow")
    if len(binetflow_files) > 1 or len(binetflow_files) == 0:
        return -1
    return binetflow_files[0]


def check_conn_label(path_to_dataset, infected_ips_list, normal_ips_list):

    print "--------- Checking conn file -------------"

    malware_label = 0
    normal_label = 0

    flow_array = []
    space = '	'
    with open(path_to_dataset + '/bro/conn.log') as f:

        for line in f:
            newline = line
            if not('#' == line[0]):
                split = line.split('	')
                src_address = split[2]

                err = 0
                if src_address in infected_ips_list:
                    newline = line.rstrip() + space + "From-Botnet" + "\n"
                    err += 1
                    malware_label += 1

                if src_address in normal_ips_list:
                    newline = line.rstrip() + space + "From-Normal" + "\n"
                    err += 1
                    normal_label += 1

                if err == 0:
                    newline = line.rstrip() + space + "Background" + "\n"

                if err > 1:
                    print "Error: SrcAddress has more classes. Program is terminated."
                    break
            else:
                if 'fields' in line:
                    newline = line.rstrip() + space + "label" + "\n"
                elif 'types' in line:
                    newline = line.rstrip() + space + "string" + "\n"

            flow_array.append(newline)
    f.close()

    print "malwares:", malware_label
    print "normals:", normal_label

    return flow_array


def process_binetflow_2(entire_path_to_binetflow):
        print "<<< MakeLabel <<<"
        print "<<< Reading binetflow:"
        print "     <<<", entire_path_to_binetflow
        print ""



        infected_ips_list = []
        normal_ips_list = []

        try:
            with open(entire_path_to_binetflow) as f:
                for line in f:
                    if 'StartTime' in line:
                        continue
                    split = line.split(',')

                    # split[3] - SrcAddress
                    # split[6] - DstAddress
                    label = split[14]
                    src_address = split[3]

                    if 'From-Botnet' in label:
                        if not(src_address in infected_ips_list):
                            infected_ips_list.append(src_address)

                    elif 'From-Normal' in label:
                        if not(src_address in normal_ips_list):
                            normal_ips_list.append(src_address)
            f.close()
        except TypeError:
            print "Error: Can not read binetflow file."

        print "In our infected ips list is:", infected_ips_list
        print "In our normal ips list is:", normal_ips_list
        return infected_ips_list, normal_ips_list

def write_conn_2(path, flow_array):
    print "<< Writing new flows to conn_label.log."
    index = 0
    with open(path + '/bro/conn_label.log', 'w') as f:
        for i in range(len(flow_array)):
            f.write(flow_array[i])
            index += 1
    f.close()
    print "     << Number of lines:", index
    print "<< New file conn_label.log was succesfly created."

"""
Take labels from binetflows file and then label conn.log
"""
def take_label_from_binet_flow(path):
    path_to_binet = find_name_of_binetflow(path)
    infected_ips_list, normal_ips_list = process_binetflow_2(path_to_binet)
    flow_array = check_conn_label(path, infected_ips_list, normal_ips_list)
    write_conn_2(path, flow_array)


"""
IPs are given as array in argument
"""
def ips_from_array(path, infected_ips_list, normal_ips_list):
    flow_array = check_conn_label(path, infected_ips_list, normal_ips_list)
    write_conn_2(path, flow_array)


if __name__ == '__main__':

    if len(sys.argv) == 2:
        path = sys.argv[1]
    else:
        path = None

    take_label_from_binet_flow(path)

