import os
from time import time
import _ConfigureManager
from ExtractFeatures import ExtractFeatures
from ComputeFeatures import ComputeFeatures

def main():
    # Start to count the time.
    t0 = time()

    # Load path to dataset from config file.
    # [0] is path to dataset.
    path_to_dataset = _ConfigureManager.read_config('./_config.cfg')[0]

    # Create new instance.
    extract_features = ComputeFeatures()

    # Go throw all subset in dataset.
    for sub_set in os.listdir(path_to_dataset):
        extract_features.extraction_manager(path_to_dataset + sub_set + '/bro/')
        break

    # Compute features and save them.
    extract_features.print_some()

    print "<<< All dataset successfully finished in aproximate time: %f" % ((time() - t0)/60.0) + " min."

def karel(x):
    print x

def get_list():
    return ['a', 'b', 'c']

if __name__ == '__main__':
    path_to_dataset = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset/bro/conn.log'
    path_to_dataset = os.path.dirname(path_to_dataset)
    print path_to_dataset
    path_to_dataset = os.path.dirname(path_to_dataset)
    print path_to_dataset
    print "karel a mele nohama"
