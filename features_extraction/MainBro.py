import os
import sys
sys.path.insert(0, os.environ['HOME'] + '/BotnetDetectionThesis/')

from time import time
import datetime
from ComputeFeatures import ComputeFeatures
import config as c
import os
from DNSFeatures import DNSFeatures
from logger import get_logger

logger = get_logger('debug')

def main():
    # Start to count the time.
    start_time = time()

    # Create new instance.
    extract_features = ComputeFeatures()

    print " << Loading top alexa: "
    DNSFeatures.load_all_top_alexa()
    print "     << Loaded top alexa: "

    # Go throw all subset in dataset.
    index = 1
    for sub_set in os.listdir(c.datasets_folder):
        if sub_set.startswith("."):
            continue
        logger.info("--------------------------------------------------------")
        logger.info("-------- #{} {} extraction".format(index, sub_set))
        logger.info("--------------------------------------------------------")

        extract_features.extraction_manager(c.datasets_folder + sub_set + '/bro/')
        index += 1

    # Add certificate to connections that does not contain any certificate.
    extract_features.add_cert_to_non_cert_conn()

    # Compute features and save them.
    #extract_features.create_dataset_dns()
    logger.info("computing features...")
    extract_features.create_balanced_dataset()

    # Print final statistic
    extract_features.print_statistic()
    # Extract_features.compute_features()
    extract_features.save_dataset_information()

    total_time = datetime.timedelta(seconds=time() - start_time)
    print "<<< All dataset successfully finished in aproximate time: " + str(total_time)


if __name__ == '__main__':
   main()
