import os


def main():
    # Go through all dataset and label conn logs.
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset2/unpack_logs/'
    dir_n = 0
    for dir in os.listdir(dataset_path):
        print "#" + str(dir_n) + " " + dir
        dir_n += 1

        bro_path = dataset_path + dir + '/bro/'
        for log in os.listdir(bro_path):
            if '_label' in log:
                print "Error: there is still conn_label.log."


if __name__ == '__main__':
    main()