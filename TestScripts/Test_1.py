import os
import time
from datetime import datetime
import pytz
import numpy as np
from sklearn.utils import shuffle

def main():
    # Go through all dataset and label conn logs.
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_2_normal/unpack_logs/'
    dir_n = 0
    for dir in os.listdir(dataset_path):
        print "#" + str(dir_n) + " " + dir
        dir_n += 1

        bro_path = dataset_path + dir + '/bro/'
        for log in os.listdir(bro_path):
            if '_label' in log:
                print "Error: there is still conn_label.log."


if __name__ == '__main__':

    # arr = np.arange(1000)
    # print arr
    # np.random.shuffle(arr)
    # print arr

    X = [1,2,3,4,5]
    y = ['auto', 'kun', 'lopata', 'vidle', 'lovec']

    X, y = shuffle(X, y, random_state=43)
    print X
    print y