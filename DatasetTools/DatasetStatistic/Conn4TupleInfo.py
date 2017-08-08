import os
from Connection4tupleStatis import Connection4tupleStatis


class Conn4TupleInfo:
    def __init__(self):
        self.connection_4_tuples = dict()
        self.conn_dict = dict()
        self.control_ssl_uids_dict = dict()

    def read_ssl_log(self, path_to_label_ssl):

        hit = 0
        lines = 0
        ssl_lines_without_conn = 0
        with open(path_to_label_ssl) as ssl_file:
            for ssl_line in ssl_file:
                if '#' == ssl_line[0]:
                    continue

                lines += 1

                ssl_split = ssl_line.split('	')
                ssl_uid = ssl_split[1]

                # if same ssl, continue (in some ssl.log files are more same ssl lines. It is probably bro error)
                try:
                    if self.control_ssl_uids_dict[ssl_uid]:
                        if ssl_line == self.control_ssl_uids_dict[ssl_uid]:
                            continue
                        else:
                            print "More ssl uids:"
                            print "Old ssl:"
                            print self.control_ssl_uids_dict[ssl_uid]
                            print "New ssl:"
                            print ssl_line
                except:
                    self.control_ssl_uids_dict[ssl_uid] = ssl_line

                # find flow in conn.log by this ssl uid.
                try:
                    conn_log = self.conn_dict[ssl_uid]
                    hit += 1
                except:
                    # print "Error: ssl log does not have conn log!!! Program is terminated."
                    ssl_lines_without_conn += 1
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

        self.control_ssl_uids_dict = dict()
        print "     <<< Hit conn: ", hit
        print "     <<< No hit conn: ", ssl_lines_without_conn
        print "     <<< Lines: ", lines

    def read_conn_log(self, path_to_label_conn):
        try:
            with open(path_to_label_conn) as f:
                for line in f:
                    if '#' == line[0]:
                        continue
                    split = line.split('	')
                    conn_uid = split[1]
                    label = split[21]
                    if 'Background' in label or 'No_Label' in label:
                        continue
                    try:
                        if self.conn_dict[conn_uid]:
                            print "Error: There are more conn log with same uid !!!"
                    except:
                        self.conn_dict[conn_uid] = line
            f.close()
        except:
            print "Error: " + path_to_label_conn + " does not exist."

    def read_all_conn_logs(self, path_to_folder):
        self.conn_dict = dict()
        for conn_log in os.listdir(path_to_folder):
            if conn_log.endswith('.log') and 'conn.' in conn_log and '_label' in conn_log:
                # print "Cesta: " + path_to_folder + conn_log
                self.read_conn_log(path_to_folder + conn_log)

    def find_all_ssl_log(self, path_to_subset):
        for ssl_file in os.listdir(path_to_subset):
            if ssl_file.endswith('.log') and 'ssl.' in ssl_file:
                print "  << SSL log", ssl_file
                self.read_ssl_log(path_to_subset + ssl_file)

    """
    Statistic methods.
    """
    def print_statistic(self):
        print "Number of conn_4_tuple:", len(self.connection_4_tuples.keys())


def main():
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset/'
    conn_4tuple_stat = Conn4TupleInfo()

    index = 1
    for sub_dir in os.listdir(dataset_path):
        print "-------- #" + str(index) + " " + sub_dir
        print "--------------------------------------------------------"
        conn_4tuple_stat.read_all_conn_logs(dataset_path + sub_dir + '/bro/')
        conn_4tuple_stat.find_all_ssl_log(dataset_path + sub_dir + '/bro/')
        index += 1

    conn_4tuple_stat.print_statistic()

if __name__ == '__main__':
    main()