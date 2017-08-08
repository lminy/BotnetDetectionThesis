import os


class ExtractFeatures(object):

    def __init__(self):
        self.connection_4_tuples = dict()

        self.conn_dict = dict()
        self.x509_dict = dict()
        self.control_ssl_uids_dict = dict()

    def extraction_manager(self, dataset_path_to_logs):
        # Loads all conn logs in bro folder.
        self.conn_logs(dataset_path_to_logs)
        # Loads all x509 logs in bro folder.
        self.x509_logs(dataset_path_to_logs)
        # Load all ssl logs.



    """
    ---------------------- Conn logs. -------------------------
    """
    def conn_logs(self, dataset_path_to_logs):
        # Clear conn_dict()
        self.conn_dict = dict()
        all_conn_logs = get_such_logs(dataset_path_to_logs, ['conn', '_label'])
        for conn_log in all_conn_logs:
            self.read_conn_log(dataset_path_to_logs + conn_log)
        print "     << Loaded conn logs: ", len(all_conn_logs)

    def read_conn_log(self, dataset_path_to_conn):
        try:
            with open(dataset_path_to_conn) as f:
                for line in f:
                    if line[0] == '#':
                        continue
                    split_conn_line = line.split('	')
                    conn_uid = split_conn_line[1]
                    label = split_conn_line[21]

                    if 'Background' in label or 'No_Label' in label:
                        continue

                    try:
                        if self.conn_dict[conn_uid]:
                            print "Error: There are conn logs with same uid !!!"
                    except:
                        self.conn_dict[conn_uid] = line
            f.close()
        except IOError:
            print "Error: The conn file: " + dataset_path_to_conn + " does not exist."

    """
    --------------------- X509 logs. ------------------------
    """
    def x509_logs(self, dataset_path_to_logs):
        # Clear x509_dict()
        self.x509_dict = dict()
        all_x509_logs = get_such_logs(dataset_path_to_logs, ['x509'])
        for x509_log in all_x509_logs:
            self.read_conn_log(dataset_path_to_logs + x509_log)
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
                        self.x509_dict[x509_uid].append(new_line)
                        print "Error: [read_x509_log] more uids in x509!!!", x509_uid,\
                            " and path is: " + dataset_path_to_logs + x509_log
                    except:
                        self.x509_dict[x509_uid] = []
                        self.x509_dict[x509_uid].append(new_line)

            f.close()
        except IOError:
            print "Error: The x509 file: " + dataset_path_to_logs + x509_log + " does not exist."

    """
    --------------------- SSL logs. ------------------------
    """
    def ssl_logs(self, dataset_path_to_logs):
        all_ssl_logs = get_such_logs(dataset_path_to_logs, ['ssl'])
        for ssl_log in all_ssl_logs:
            self.read_conn_log(dataset_path_to_logs + ssl_log)
        print "     << Loaded ssl logs: ", len(all_ssl_logs)

    def create_4_tuples(self, path_to_ssl_log):

        with open(path_to_ssl_log) as ssl_file:
            for ssl_line in ssl_file:
                if '#' == ssl_line[0]:
                    continue

                ssl_split = ssl_line.split('	')
                ssl_uid = ssl_split[1]

                # if same ssl, continue (in some ssl.log files are more same ssl lines. It is probably bro error)
                try:
                    if self.control_ssl_uids_dict[ssl_uid]:
                        continue
                except:
                    self.control_ssl_uids_dict[ssl_uid] = 1

                # find flow in conn.log by this ssl uid.
                try:
                    conn_log = self.con_dict[ssl_uid]
                except:
                    # print "Error: ssl log does not have conn log !!!"
                    # break
                    continue

                conn_split = conn_log.split('	')
                # 2-srcIpAddress, 4-dstIpAddress, 5-dstPort, 6-Protocol
                connection_index = conn_split[2], conn_split[4], conn_split[5], conn_split[6]
                try:
                    label = conn_split[21]
                except IndexError:
                    print "Error: no label in conn line."

                if 'Background' in label or 'No_Label' in label:
                    background_flows += 1
                    print "Error: Sakra divny."
                    continue

                if not ('Botnet' in label) and not ('Normal') in label:
                    print "Error: Dear more, there are more states of labels !!!!"

                # file_hitrate += self.find_uid(path_to_dataset, ssl_uid)


                try:
                    self.connection_4_tuples[connection_index].add_ssl_flow(conn_log, label)
                except:
                    self.connection_4_tuples[connection_index] = Connection4tuple(connection_index)
                    self.connection_4_tuples[connection_index].add_ssl_flow(conn_log, label)

                # x509 and ssl
                valid_x509_list = self.split_ssl(ssl_line, connection_index, label)
                number_of_adding_x509 += len(valid_x509_list)

                self.connection_4_tuples[connection_index].add_ssl_log(ssl_line, valid_x509_list,
                                                                       os.path.basename(path_to_dataset))
                number_adding_ssl += 1

                # --------- just for printing for sebas -------
                self.number_ssl_logs += 1
                self.number_x509_logs += len(valid_x509_list)

        ssl_file.close()

        self.con_dict = dict()
        self.x509_dict = dict()
        self.control_ssl_uids_dict = dict()
        # Just pint information about file and 4-tuples and their flows.
        self.count_statistic_of_conn(count_lines, background_flows, number_adding_ssl, number_of_adding_x509)
        # print "number_not_adding_ssl", self.not_added_x509



def get_such_logs(path_to_logs, part_name_list):
    searched_list = []
    for searched_file in os.listdir(path_to_logs):
        if all(x in searched_file for x in part_name_list):
            searched_list.append(searched_file)
    return searched_list
