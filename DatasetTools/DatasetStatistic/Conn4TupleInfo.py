import os
from Connection4tupleStatis import Connection4tupleStatis


class Conn4TupleInfo:
    def __init__(self):
        self.connection_4_tuples = dict()
        self.control_ssl_uids_dict = dict()

        self.conn_dict = dict()

    def read_ssl_log(self, path_to_label_ssl):

        unhit = 0
        with open(path_to_label_ssl) as ssl_file:
            for ssl_line in ssl_file:
                if '#' == ssl_line[0]:
                    continue

                ssl_split = ssl_line.split('	')
                ssl_uid = ssl_split[1]

                # if same ssl, continue (in some ssl.log files are more same ssl lines. It is probably bro error)
                try:
                    if self.control_ssl_uids_dict[ssl_uid]:
                        if ssl_line == self.control_ssl_uids_dict[ssl_uid]:
                            continue
                        else:
                            # print "--------------- More ssl uids ------------------------------"
                            # print "Old ssl:"
                            # print self.control_ssl_uids_dict[ssl_uid]
                            # print "New ssl:"
                            # print ssl_line

                            old_ssl_split = self.control_ssl_uids_dict[ssl_uid].split('	')
                            new_ssl_split = ssl_line.split('	')
                            for i in range(0, len(old_ssl_split)):
                                if i <= 20:
                                    if old_ssl_split[i] != new_ssl_split[i]:
                                        print "SSL Error - ssl lines with same uid are not same !!!"
                                        print "     < Path:", path_to_label_ssl
                                        print "     < ssl uid:", ssl_uid
                            continue
                except:
                    self.control_ssl_uids_dict[ssl_uid] = ssl_line

                # find flow in conn.log by this ssl uid.
                try:
                    conn_log = self.conn_dict[ssl_uid]
                except:
                    # conn_dict contains only normal or malware conn lines. Here there are read all ssl lines and
                    # some ssl lines shows to background conn_line that are not contained in conn_dict.
                    continue

                conn_split = conn_log.split('	')
                # 2-srcIpAddress, 4-dstIpAddress, 5-dstPort, 6-Protocol
                connection_index = conn_split[2], conn_split[4], conn_split[5], conn_split[6]
                try:
                    label = conn_split[21]
                except IndexError:
                    print "Error: no label in conn line. Program is terminated."
                    break

                if not ('Botnet' in label) and not ('Normal') in label:
                    print "Error: Dear more, there are more states of labels !!!!"

                try:
                    self.connection_4_tuples[connection_index].add_ssl_flow(conn_log, label)
                except:
                    self.connection_4_tuples[connection_index] = Connection4tupleStatis(connection_index)
                    self.connection_4_tuples[connection_index].add_ssl_flow(conn_log, label)
        ssl_file.close()

    def find_all_ssl_log(self, path_to_subset):
        print "Reading ssl logs:"
        self.control_ssl_uids_dict = dict()
        for ssl_file in os.listdir(path_to_subset):
            if ssl_file.endswith('.log') and 'ssl' in ssl_file:
                print "  << SSL log", ssl_file
                self.read_ssl_log(path_to_subset + ssl_file)

    """
      --------------------- X509 logs. ------------------------
      """

    def x509_logs(self, dataset_path_to_logs):
        print "<< Read all x509 logs:"
        # Clear x509_dict()
        self.x509_dict = dict()
        all_x509_logs = get_such_logs(dataset_path_to_logs, ['x509'])
        print "num x509 logs:", len(all_x509_logs)
        for x509_log in all_x509_logs:
            self.read_x509_log(dataset_path_to_logs, x509_log)
        print "     << Loaded x509 logs: ", len(all_x509_logs)

    def read_x509_log(self, dataset_path_to_logs, x509_log):
        """
        Read started_file.txt where is time when capture of this dataset starts. Some datasets have starting
        time 1.1. 1970 00:00:00. So we have to add to time.
        If this file does not exist, dataset has right value time.
        """
        # go to parent folder, because 'started_file.txt' is saved in sub folder. Not in bro folder.
        sub_folder = os.path.dirname(dataset_path_to_logs)
        started_unix_time = 0.0
        try:
            with open(sub_folder + "/start_date.txt") as f:
                started_unix_time = float(f.readlines()[1])
                print "     << Started unix time file was read in:", sub_folder
            f.close()
        except IOError:
            pass

        try:
            with open(dataset_path_to_logs + x509_log) as f:
                # go throw ssl file line by line and for each ssl line check all uid of flows
                for line in f:
                    if '#' == line[0]:
                        continue
                    x509_split = line.split('	')

                    """
                    Change time, because some datasets are from 1.1 1970 00:00:00.
                    """
                    time_new = float(x509_split[0]) + started_unix_time
                    new_line = str(time_new)
                    for i in range(1, len(x509_split)):
                        new_line += '	' + x509_split[i]

                    x509_uid = x509_split[1]
                    try:
                        if self.x509_dict[x509_uid]:
                            print "Error: [read_x509_log] more uids in x509!!!", x509_uid, \
                                " and path is: " + dataset_path_to_logs + x509_log
                    except:
                        self.x509_dict[x509_uid] = new_line

            f.close()
        except IOError:
            print "Error: The x509 file: " + dataset_path_to_logs + x509_log + " does not exist."

    def read_conn_log(self, path_to_label_conn):

        unhit = 0
        normal = 0
        malware = 0

        n_line = 0
        try:
            with open(path_to_label_conn) as f:
                for line in f:
                    if '#' == line[0]:
                        continue

                    split = line.split('	')
                    conn_uid = split[1]
                    label = split[21]

                    if 'Normal' in label:
                        normal += 1
                    if 'Botnet' in label:
                        malware += 1

                    if 'Background' in label or 'No_Label' in label:
                        unhit += 1
                        continue

                    try:
                        if self.conn_dict[conn_uid]:
                            print "Error: more same conn line !!!!!"
                    except:
                        self.conn_dict[conn_uid] = line

            f.close()


        except:
            print "Error: " + path_to_label_conn + " does not exist."

    def read_all_conn_logs(self, path_to_folder):
        print "Reading conn logs:"
        for conn_log in os.listdir(path_to_folder):
            if conn_log.endswith('.log') and 'conn' in conn_log and '_label' in conn_log:
                # print "Cesta: " + path_to_folder + conn_log
                print " << conn log:"
                self.read_conn_log(path_to_folder + conn_log)

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


def get_such_logs(path_to_logs, part_name_list):
    searched_list = []
    for searched_file in os.listdir(path_to_logs):
        if all(x in searched_file for x in part_name_list):
            searched_list.append(searched_file)
    return searched_list


def main():
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset/'
    conn_4tuple_stat = Conn4TupleInfo()

    index = 1
    for sub_dir in os.listdir(dataset_path):
        print "--------------------------------------------------------"
        print "-------- #" + str(index) + " " + sub_dir
        print "--------------------------------------------------------"
        conn_4tuple_stat.read_all_conn_logs(dataset_path + sub_dir + '/bro/')
        conn_4tuple_stat.x509_logs(dataset_path + sub_dir + '/bro/')
        conn_4tuple_stat.find_all_ssl_log(dataset_path + sub_dir + '/bro/')
        index += 1
        break

    conn_4tuple_stat.print_statistic()

if __name__ == '__main__':
    main()
