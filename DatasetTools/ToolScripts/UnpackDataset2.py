""""
This script unpack Dataset2 to some destination place and rename it from '%3A' to '_'.
"""

import os
import gzip
import datetime


def unpackGZ(path):
    with gzip.open(path, 'rb') as f:
        file_content = f.read()
    f.close()
    return file_content

def writeToFile(path_dst, file_content):
    with open(path_dst, 'w') as f:
        f.write(file_content)
    f.close()
def change_name(name):
    name = name.replace('%3A', '_')
    name = name.replace('.gz', '')
    return name





# gyjgfyj


def main():
    # path_to_dataset = "/home/frenky/Documents/HTTPSDetecor/DatasetTemp/logs/"
    # dst_path = "/home/frenky/Documents/HTTPSDetecor/DatasetTemp/logs2/"

    # path_to_dataset = "/home/frenky/Documents/HTTPSDetecor/Dataset2/logs/"
    # dst_path = "/home/frenky/Documents/HTTPSDetecor/Dataset2/unpack_logs/"

    path_to_dataset = "/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset2/logs/"
    dst_path = "/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset2/unpack_logs/"

    j = 0
    for dir in os.listdir(path_to_dataset):
        sub_path = path_to_dataset + dir + '/'

        print "------------ " + "#" + str(j) + " " + sub_path + " ----------------"

        i = 0
        j += 1
        for log_name in os.listdir(sub_path):
            ssub_path = sub_path + log_name
            # print '#' + str(i) + " " + ssub_path

            file_content = unpackGZ(ssub_path)
            name = change_name(os.path.basename(log_name))

            dst_folder = dst_path + dir + '/'
            if not os.path.exists(dst_folder):
                os.makedirs(dst_folder)
            writeToFile(dst_folder + name, file_content)
            i += 1

    print "Visited folders:" + str(j)


if __name__ == '__main__':

    main()