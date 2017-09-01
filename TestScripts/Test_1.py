import os
import time
from datetime import datetime
import pytz
import numpy as np
from sklearn.utils import shuffle



def read_ssl(path, ssl_dict):
    print "----------------- ssl log -----------------"
    with open(path) as ssl_file:
        for line in ssl_file:
            if line[0] == '#':
                continue
            split_line = line.split('	')
            ssl_uid = split_line[1]
            try:
                if ssl_dict[ssl_uid]:
                    # print "Error: more uids in ssl line..."
                    pass
            except:
                print line
                ssl_dict[ssl_uid] = line
    ssl_file.close()
    return ssl_dict


def read_conn(path, ssl_dict):
    print "----------------- conn log -----------------"
    index = 0
    with open(path) as f:
        for line in f:
            if line[0] == '#':
                continue
            split_conn = line.split('	')
            conn_uid = split_conn[1]

            try:
                if ssl_dict[conn_uid]:
                    print split_conn[21]
                    index += 1
            except:
                # print "Error: can not find conn line."
                pass

if __name__ == '__main__':
    path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/test_dataset/CTU-Malware-Capture-Botnet-116-2/'
    ssl_dict = dict()
    read_ssl(path + 'bro/ssl.log', ssl_dict)
    read_conn(path + 'bro/conn_label.log', ssl_dict)
