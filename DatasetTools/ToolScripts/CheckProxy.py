"""
This script goes trough dataset opens the x509 logs a try to find "mitmproxy" word.
"""
import os

"""
Just load x509.log to dictionary.
"""


def load_x509_file(path_to_dataset):

    is_proxy = False
    try:
        with open(path_to_dataset + "/bro/x509.log") as f:
            # go thru ssl file line by line and for each ssl line check all uid of flows
            for line in f:
                if '#' == line[0]:
                    continue
                split = line.split('	')

                if 'mitmproxy' in line:
                    is_proxy = True
                    break

        f.close()
    except IOError:
        print "Error: No x509 file."
    return is_proxy

def main():
    dataset_path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_2_malware/no_proxy'

    for sub_dir in os.listdir(dataset_path):
        is_proxy = load_x509_file(dataset_path + sub_dir)
        if not is_proxy:
            print "is proxy:", is_proxy
            print dataset_path + sub_dir

if __name__ == '__main__':
    main()