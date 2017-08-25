import os

class ExtractFeatures(object):

    def __init__(self):
        self.connection_4_tuples = dict()

        self.x509_dict = dict()
        self.control_ssl_uids_dict = dict()

        self.conn_dict_arr = []
        self.conn_dict_index = 0
        self.number_conn_lines = 0

        self.err_conn_uids = 0
        self.err_more_same_X509 = 0
        self.err_not_added_x509 = 0

        self.ssl_lines = 0
        self.not_founded_x509_lines = 0
        self.founded_x509_lines = 0


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
                            if self.x509_dict[x509_uid] == new_line:
                                pass
                            else:
                                self.err_more_same_X509 += 1
                                # print "Error: [read_x509_log] more uids in x509!!!", x509_uid,\
                                #     " and path is: " + dataset_path_to_logs + x509_log
                                print "-----------------------------------------"
                                print "old:", self.x509_dict[x509_uid]
                                print "new:", new_line
                                print "-----------------------------------------"
                                # print "-----------------------------------------"
                                # print " <<< old one:"
                                # index = 0
                                # for col in self.x509_dict[x509_uid].split('	'):
                                #     print str(index) + ' - ' + col
                                #     index += 1
                                # print " <<< new one:"
                                # index = 0
                                # for col in new_line.split('	'):
                                #     print str(index) + ' - ' + col
                                #     index += 1
                                # print "-----------------------------------------"
                    except:
                        self.x509_dict[x509_uid] = new_line

            f.close()
        except IOError:
            print "Error: The x509 file: " + dataset_path_to_logs + x509_log + " does not exist."


def get_such_logs(path_to_logs, part_name_list):
    searched_list = []
    for searched_file in os.listdir(path_to_logs):
        if all(x in searched_file for x in part_name_list):
            searched_list.append(searched_file)
    return searched_list


def main():
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_2_normal/unpack_logs/'
    # dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_1_malware/'
    conn_4tuple_stat = ExtractFeatures()
    index = 1
    for sub_dir in os.listdir(dataset_path):
        print "--------------------------------------------------------"
        print "-------- #" + str(index) + " " + sub_dir
        print "--------------------------------------------------------"
        conn_4tuple_stat.x509_logs(dataset_path + sub_dir + '/bro/')

if __name__ == '__main__':
    main()