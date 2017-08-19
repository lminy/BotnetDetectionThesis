"""
Delete files in directory according
"""
import os


def delete_file(dataset_path_to_bro, file_name):
    for log in os.listdir(dataset_path_to_bro):
        if file_name in log:
            print "We are deleting this file:"
            print dataset_path_to_bro + log
            os.remove(dataset_path_to_bro + log)


def main():
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_2_normal/unpack_logs/'

    index = 1
    for sub_dir in os.listdir(dataset_path):
        print "--------------------------------------------------------"
        print "-------- #" + str(index) + " " + sub_dir
        print "--------------------------------------------------------"
        delete_file(dataset_path + sub_dir + '/bro/', '_label')


if __name__ == '__main__':
    main()
