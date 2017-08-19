import os
from Connection4tupleStatis import Connection4tupleStatis
import pandas
import numpy as np


class Conn4TupleInfo:
    def __init__(self):
        self.connection_4_tuples = dict()
        self.control_ssl_uids_dict = dict()
        self.conn_dict = pandas.DataFrame(dict(), index=[0])

        self.conn_dict_index = 0
        self.number_conn_lines = 0

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
        self.number_conn_lines = 0
        for ssl_file in os.listdir(path_to_subset):
            if ssl_file.endswith('.log') and 'ssl' in ssl_file:
                print "  << SSL log", ssl_file
                self.read_ssl_log(path_to_subset + ssl_file)

    def read_conn_log(self, path_to_label_conn):

        unhit = 0
        normal = 0
        malware = 0
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

                    self.number_conn_lines += 1
                    if self.number_conn_lines % 1000 == 0:
                        print self.number_conn_lines

                    # 25780221 should normal or malware

                    try:
                        if self.conn_dict[conn_uid]:
                            print "Error: There are more conn log with same uid !!!"
                    except:
                        self.conn_dict[conn_uid] = line


            f.close()
        except:
            print "Error: " + path_to_label_conn + " does not exist."

    def read_all_conn_logs(self, path_to_folder):
        # Clean conn_dict_arr.
        print "Deleting ..."
        self.conn_dict = dict()
        print "Deleting Done"
        print "Reading conn logs:"
        for conn_log in os.listdir(path_to_folder):
            if conn_log.endswith('.log') and 'conn' in conn_log and '_label' in conn_log:
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
        for tuple_key in self.connection_4_tuples.keys():
            conn_tuple = self.connection_4_tuples[tuple_key]
            flows_together += conn_tuple.get_number_of_ssl_flows()
            # More normal labels and malware labels in one 4-tuple ?
            if conn_tuple.get_malware_label() != 0 and conn_tuple.get_normal_label() != 0:
                print "Error: More labels in one 4-tuples"
                # Same amout of labels in one 4-tuple?
                if conn_tuple.get_malware_label() == conn_tuple.get_normal_label():
                    print "Watch out baby, same amount of labels"
                    print "Normal:", conn_tuple.conn_tuple.get_normal_label()
                    print "Malware:", conn_tuple.get_malware_label()

            if conn_tuple.is_malware():
                malware_tuples += 1
            else:
                normal_tuples += 1

        print "Number of all 4_tuples:", len(self.connection_4_tuples.keys())
        print "Number of normal 4-tuples:", normal_tuples
        print "Number of malware 4-tuples:", malware_tuples
        print "All gathered flows:", flows_together


def main():
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset/'
    conn_4tuple_stat = Conn4TupleInfo()

    index = 1
    for sub_dir in os.listdir(dataset_path):
        print "--------------------------------------------------------"
        print "-------- #" + str(index) + " " + sub_dir
        print "--------------------------------------------------------"
        conn_4tuple_stat.read_all_conn_logs(dataset_path + sub_dir + '/bro/')
        conn_4tuple_stat.find_all_ssl_log(dataset_path + sub_dir + '/bro/')
        index += 1

    conn_4tuple_stat.print_statistic()

if __name__ == '__main__':
    main()
