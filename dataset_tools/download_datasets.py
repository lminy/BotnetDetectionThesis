"""
Download all datasets which have bro folder.
USAGE:
python download_datasets.py https://mcfp.felk.cvut.cz/publicDatasets/
"""

import sys
from bs4 import BeautifulSoup
import requests
import requests.packages.urllib3.exceptions
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
import urllib2
import ssl
import os
import shutil
import config as c
import time
import datetime
from logger import get_logger


import logging
#import config as c


logger = get_logger('debug')


files_to_download = ["ssl.log", "x509.log", "weird.log", "conn.log", "dns.log"]

# Normal datasets
datasets_to_download = [
'CTU-Normal-20/',
'CTU-Normal-21/',
'CTU-Normal-22/',
'CTU-Normal-23/',
'CTU-Normal-24/',
'CTU-Normal-25/',
'CTU-Normal-26/',
'CTU-Normal-27/',
'CTU-Normal-28/',
'CTU-Normal-29/',
'CTU-Normal-30/',
'CTU-Normal-31/',
'CTU-Normal-32/'
]

# THE CTU-13 DATASET
datasets_to_download = [
'CTU-Malware-Capture-Botnet-42/',
'CTU-Malware-Capture-Botnet-43/',
'CTU-Malware-Capture-Botnet-44/',
'CTU-Malware-Capture-Botnet-45/',
'CTU-Malware-Capture-Botnet-46/',
'CTU-Malware-Capture-Botnet-47/',
'CTU-Malware-Capture-Botnet-48/',
'CTU-Malware-Capture-Botnet-49/',
'CTU-Malware-Capture-Botnet-50/',
'CTU-Malware-Capture-Botnet-51/',
'CTU-Malware-Capture-Botnet-52/',
'CTU-Malware-Capture-Botnet-53/',
'CTU-Malware-Capture-Botnet-54/',
]

# Whole datasets
datasets_to_download = ["CTU-Malware-Capture-Botnet-1", "CTU-Malware-Capture-Botnet-102", "CTU-Malware-Capture-Botnet-111-1", "CTU-Malware-Capture-Botnet-116-1", "CTU-Malware-Capture-Botnet-116-2", "CTU-Malware-Capture-Botnet-138-1", "CTU-Malware-Capture-Botnet-157-1", "CTU-Malware-Capture-Botnet-163-1", "CTU-Malware-Capture-Botnet-164-1", "CTU-Malware-Capture-Botnet-169-1", "CTU-Malware-Capture-Botnet-169-2", "CTU-Malware-Capture-Botnet-169-3", "CTU-Malware-Capture-Botnet-17-1", "CTU-Malware-Capture-Botnet-17-2", "CTU-Malware-Capture-Botnet-174-1", "CTU-Malware-Capture-Botnet-175-1", "CTU-Malware-Capture-Botnet-177-1", "CTU-Malware-Capture-Botnet-178-1", "CTU-Malware-Capture-Botnet-179-1", "CTU-Malware-Capture-Botnet-180-1", "CTU-Malware-Capture-Botnet-181-1", "CTU-Malware-Capture-Botnet-183-1", "CTU-Malware-Capture-Botnet-184-1", "CTU-Malware-Capture-Botnet-185-1", "CTU-Malware-Capture-Botnet-186-1", "CTU-Malware-Capture-Botnet-187-1", "CTU-Malware-Capture-Botnet-188-1", "CTU-Malware-Capture-Botnet-188-2", "CTU-Malware-Capture-Botnet-188-3", "CTU-Malware-Capture-Botnet-188-4", "CTU-Malware-Capture-Botnet-189-1", "CTU-Malware-Capture-Botnet-189-2", "CTU-Malware-Capture-Botnet-193-1", "CTU-Malware-Capture-Botnet-193-2", "CTU-Malware-Capture-Botnet-194-1", "CTU-Malware-Capture-Botnet-195-1", "CTU-Malware-Capture-Botnet-196-1", "CTU-Malware-Capture-Botnet-198-1", "CTU-Malware-Capture-Botnet-199-1", "CTU-Malware-Capture-Botnet-199-2", "CTU-Malware-Capture-Botnet-200-1", "CTU-Malware-Capture-Botnet-201-1", "CTU-Malware-Capture-Botnet-202-1", "CTU-Malware-Capture-Botnet-203-1", "CTU-Malware-Capture-Botnet-204-1", "CTU-Malware-Capture-Botnet-205-1", "CTU-Malware-Capture-Botnet-205-2", "CTU-Malware-Capture-Botnet-208-2", "CTU-Malware-Capture-Botnet-209-1", "CTU-Malware-Capture-Botnet-210-1", "CTU-Malware-Capture-Botnet-211-1", "CTU-Malware-Capture-Botnet-211-2", "CTU-Malware-Capture-Botnet-213-1", "CTU-Malware-Capture-Botnet-215-1", "CTU-Malware-Capture-Botnet-215-2", "CTU-Malware-Capture-Botnet-217-1", "CTU-Malware-Capture-Botnet-218-1", "CTU-Malware-Capture-Botnet-219-1", "CTU-Malware-Capture-Botnet-219-2", "CTU-Malware-Capture-Botnet-219-3", "CTU-Malware-Capture-Botnet-220-1", "CTU-Malware-Capture-Botnet-221-1", "CTU-Malware-Capture-Botnet-221-2", "CTU-Malware-Capture-Botnet-222-1", "CTU-Malware-Capture-Botnet-224-1", "CTU-Malware-Capture-Botnet-227-1", "CTU-Malware-Capture-Botnet-228-1", "CTU-Malware-Capture-Botnet-230-1", "CTU-Malware-Capture-Botnet-230-2", "CTU-Malware-Capture-Botnet-231-1", "CTU-Malware-Capture-Botnet-232-1", "CTU-Malware-Capture-Botnet-235-1", "CTU-Malware-Capture-Botnet-237-1", "CTU-Malware-Capture-Botnet-238-1", "CTU-Malware-Capture-Botnet-239-1", "CTU-Malware-Capture-Botnet-240-1", "CTU-Malware-Capture-Botnet-241-1", "CTU-Malware-Capture-Botnet-242-1", "CTU-Malware-Capture-Botnet-243-1", "CTU-Malware-Capture-Botnet-244-1", "CTU-Malware-Capture-Botnet-245-1", "CTU-Malware-Capture-Botnet-246-1", "CTU-Malware-Capture-Botnet-247-1", "CTU-Malware-Capture-Botnet-248-1", "CTU-Malware-Capture-Botnet-249-1", "CTU-Malware-Capture-Botnet-25-1", "CTU-Malware-Capture-Botnet-25-2", "CTU-Malware-Capture-Botnet-25-3", "CTU-Malware-Capture-Botnet-25-4", "CTU-Malware-Capture-Botnet-25-5", "CTU-Malware-Capture-Botnet-25-6", "CTU-Malware-Capture-Botnet-251-1", "CTU-Malware-Capture-Botnet-253-1", "CTU-Malware-Capture-Botnet-254-1", "CTU-Malware-Capture-Botnet-257-1", "CTU-Malware-Capture-Botnet-260-1", "CTU-Malware-Capture-Botnet-261-1", "CTU-Malware-Capture-Botnet-261-2", "CTU-Malware-Capture-Botnet-261-3", "CTU-Malware-Capture-Botnet-261-4", "CTU-Malware-Capture-Botnet-263-1", "CTU-Malware-Capture-Botnet-264-1", "CTU-Malware-Capture-Botnet-265-1", "CTU-Malware-Capture-Botnet-266-1", "CTU-Malware-Capture-Botnet-267-1", "CTU-Malware-Capture-Botnet-270-1", "CTU-Malware-Capture-Botnet-273-1", "CTU-Malware-Capture-Botnet-274-1", "CTU-Malware-Capture-Botnet-275-1", "CTU-Malware-Capture-Botnet-277-1", "CTU-Malware-Capture-Botnet-278-1", "CTU-Malware-Capture-Botnet-279-1", "CTU-Malware-Capture-Botnet-280-1", "CTU-Malware-Capture-Botnet-281-1", "CTU-Malware-Capture-Botnet-282-1", "CTU-Malware-Capture-Botnet-285-1", "CTU-Malware-Capture-Botnet-287-1", "CTU-Malware-Capture-Botnet-290-1", "CTU-Malware-Capture-Botnet-291-1", "CTU-Malware-Capture-Botnet-292-1", "CTU-Malware-Capture-Botnet-293-1", "CTU-Malware-Capture-Botnet-294-1", "CTU-Malware-Capture-Botnet-295-1", "CTU-Malware-Capture-Botnet-296-1", "CTU-Malware-Capture-Botnet-297-1", "CTU-Malware-Capture-Botnet-299-1", "CTU-Malware-Capture-Botnet-300-1", "CTU-Malware-Capture-Botnet-301-1", "CTU-Malware-Capture-Botnet-302-1", "CTU-Malware-Capture-Botnet-303-1", "CTU-Malware-Capture-Botnet-305-1", "CTU-Malware-Capture-Botnet-305-2", "CTU-Malware-Capture-Botnet-306-1", "CTU-Malware-Capture-Botnet-308-1", "CTU-Malware-Capture-Botnet-31-1", "CTU-Malware-Capture-Botnet-315-1", "CTU-Malware-Capture-Botnet-318-1", "CTU-Malware-Capture-Botnet-320-1", "CTU-Malware-Capture-Botnet-320-2", "CTU-Malware-Capture-Botnet-321-1", "CTU-Malware-Capture-Botnet-322-1", "CTU-Malware-Capture-Botnet-323-1", "CTU-Malware-Capture-Botnet-324-1", "CTU-Malware-Capture-Botnet-325-1", "CTU-Malware-Capture-Botnet-326-1", "CTU-Malware-Capture-Botnet-327-1", "CTU-Malware-Capture-Botnet-327-2", "CTU-Malware-Capture-Botnet-328-1", "CTU-Malware-Capture-Botnet-329-1", "CTU-Malware-Capture-Botnet-334-1", "CTU-Malware-Capture-Botnet-335-1", "CTU-Malware-Capture-Botnet-336-1", "CTU-Malware-Capture-Botnet-339-1", "CTU-Malware-Capture-Botnet-340-1", "CTU-Malware-Capture-Botnet-341-1", "CTU-Malware-Capture-Botnet-344-1", "CTU-Malware-Capture-Botnet-345-1", "CTU-Malware-Capture-Botnet-346-1", "CTU-Malware-Capture-Botnet-348-1", "CTU-Malware-Capture-Botnet-349-1", "CTU-Malware-Capture-Botnet-350-1", "CTU-Malware-Capture-Botnet-352-1", "CTU-Malware-Capture-Botnet-354-1", "CTU-Malware-Capture-Botnet-42", "CTU-Malware-Capture-Botnet-43", "CTU-Malware-Capture-Botnet-44", "CTU-Malware-Capture-Botnet-45", "CTU-Malware-Capture-Botnet-46", "CTU-Malware-Capture-Botnet-47", "CTU-Malware-Capture-Botnet-48", "CTU-Malware-Capture-Botnet-49", "CTU-Malware-Capture-Botnet-50", "CTU-Malware-Capture-Botnet-51", "CTU-Malware-Capture-Botnet-52", "CTU-Malware-Capture-Botnet-53", "CTU-Malware-Capture-Botnet-54", "CTU-Malware-Capture-Botnet-69", "CTU-Malware-Capture-Botnet-78-1", "CTU-Malware-Capture-Botnet-78-2", "CTU-Malware-Capture-Botnet-83-1", "CTU-Malware-Capture-Botnet-83-2", "CTU-Malware-Capture-Botnet-90", "CTU-Normal-12", "CTU-Normal-20", "CTU-Normal-21", "CTU-Normal-22", "CTU-Normal-23", "CTU-Normal-24", "CTU-Normal-25", "CTU-Normal-26", "CTU-Normal-27" "CTU-Normal-28", "CTU-Normal-29", "CTU-Normal-30", "CTU-Normal-31", "CTU-Normal-32", "CTU-Normal-6-filtered", "CTU-Normal-7", "CTU-Normal-8-1", "CTU-Normal-8-2", "CTU-Normal-9"]


def find_files(url):
    soup = BeautifulSoup(requests.get(url, verify=False).text, "lxml")
    hrefs = []
    for a in soup.find_all('a'):
        if 'href' in a.attrs :
            hrefs.append(a['href'])
    return hrefs


def compute_datasets_size(url):
    dataset_names = find_files(url)
    file_sizes = 0
    for i in range(len(dataset_names)):
        if dataset_names[i].replace("/", "") in datasets_to_download:
        #if 'CTU-Malware-Capture-Botnet-' in dataset_names[i] or 'CTU-Normal-' in dataset_names[i]:
            #number_name = int(dataset_names[i].split('-')[4].replace('/', ''))

            #if number_name < 248:
            #    continue

            logger.info(url + dataset_names[i])

            # Get content of the main page of dataset.
            content = find_files(url + dataset_names[i])

            # Look into open folder to files there. There are binetflow, bro, ...
            # And find the bro folder in this list.
            for j in range(len(content)):
                if 'bro' in content[j]:
                    #print dataset_names[i] + content[j]
                    file_sizes += save_manager(url, dataset_names[i])
                    break

    return file_sizes


def save_manager(url, dataset_name):
    file_sizes = 0
    bro_files = find_files(url + dataset_name + 'bro/')

    if 'ssl.log' in bro_files:
        directory_name = c.datasets_folder_general + dataset_name
        #if os.path.exists(directory_name):
        #    shutil.rmtree(directory_name)

        if not os.path.exists(directory_name):
            os.makedirs(directory_name)


        url_dataset = url + dataset_name
        for filename in find_files(url_dataset):
            # Download Readme file
            if "README" in filename and not os.path.exists(directory_name + filename):
                save_file(url_dataset + filename, directory_name + filename)
            # Download pcap file
            if "pcap" in filename and not os.path.exists(directory_name + filename):
                save_file(url_dataset + filename, directory_name + filename)
        #url_file = url + dataset_name + "README.html"
        #file_name = directory_name + "README.html"





        folder_bro = directory_name + "bro/"
        if not os.path.exists(folder_bro):
            os.makedirs(folder_bro)

        for bro_log in bro_files:
            if bro_log.endswith('.log') and bro_log in files_to_download:
                if not os.path.exists(directory_name + "bro/" + bro_log): # If file does not exists on hdd
                    logger.info(url + dataset_name)
                    url_file = url + dataset_name + 'bro/' + bro_log
                    file_sizes += save_file(url_file, folder_bro + bro_log)

    return file_sizes


def save_file(url_file, file_name):
    logger.info(url_file + " is downloading...")
    file_size = 0
    # https://stackoverflow.com/a/28052583
    req = urllib2.Request(url, headers={ 'X-Mashape-Key': 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' })
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    u = urllib2.urlopen(url_file, context=gcontext)
    meta = u.info()
    file_size += int(meta.getheaders("Content-Length")[0])

    f = open(file_name, 'wb')
    #logger.info("Downloading: %s Bytes: %s" % (file_name, file_size))

    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break

        file_size_dl += len(buffer)
        f.write(buffer)
        status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8) * (len(status) + 1)
        #logger.info(status)

    f.close()
    return file_size


if __name__ == '__main__':
    start_time = time.time()
    datasets_size = 0
    if len(sys.argv) == 2:
        url = sys.argv[1]
        datasets_size += compute_datasets_size(url)
        # find_files(url+'CTU-Malware-Capture-Botnet-31/')
    else:
        logger.error("Error: Please put argument.")
    logger.info("Complet Dataset size:" + str(datasets_size / (1024.0 * 1024.0)) + "MB")
    total_time = datetime.timedelta(seconds=time.time() - start_time)
    logger.info("Time : " + str(total_time))  # .strftime('%H:%M:%S'))

