"""
Download all datasets which have bro folder.
USAGE:
python download_datasets.py https://mcfp.felk.cvut.cz/publicDatasets/
"""

import sys
from bs4 import BeautifulSoup
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import urllib2
import ssl
import os
import shutil
#import config as c
import time
import datetime

datasets_folder = "/Volumes/Data/datasets/"

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

def find_files(url):
    soup = BeautifulSoup(requests.get(url, verify=False).text, "lxml")
    hrefs = []
    for a in soup.find_all('a'):
        #print a
        if 'href' in a.attrs :
            hrefs.append(a['href'])
    return hrefs

def compute_datasets_size(url):
    dataset_names = find_files(url)
    file_sizes = 0
    for i in range(len(dataset_names)):
        #if dataset_names[i] in datasets_to_download:
        if 'CTU-Malware-Capture-Botnet-' in dataset_names[i] or 'CTU-Normal-' in dataset_names[i]:
            #number_name = int(dataset_names[i].split('-')[4].replace('/', ''))

            #if number_name < 248:
            #    continue


            print url + dataset_names[i]

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
        directory_name = datasets_folder + dataset_name
        #if os.path.exists(directory_name):
        #    shutil.rmtree(directory_name)

        if not os.path.exists(directory_name):
            os.makedirs(directory_name)

        # Download Readme file
        url_dataset = url + dataset_name
        for filename in find_files(url_dataset):
            if "README" in filename:
                save_file(url_dataset + filename, directory_name + filename)
        #url_file = url + dataset_name + "README.html"
        #file_name = directory_name + "README.html"


        folder_bro = directory_name + "bro/"
        if not os.path.exists(folder_bro):
            os.makedirs(folder_bro)

        for bro_log in bro_files:
            if bro_log.endswith('.log') and bro_log in files_to_download:
                if not os.path.exists(directory_name + "bro/" + bro_log): # If file does not exists on hdd
                    print url + dataset_name
                    url_file = url + dataset_name + 'bro/' + bro_log
                    file_sizes += save_file(url_file, folder_bro + bro_log)

    return file_sizes


def save_file(url_file, file_name):
    print url_file, "is downloading..."
    file_size = 0
    # https://stackoverflow.com/a/28052583
    req = urllib2.Request(url, headers={ 'X-Mashape-Key': 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' })
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    u = urllib2.urlopen(url_file, context=gcontext)
    meta = u.info()
    file_size += int(meta.getheaders("Content-Length")[0])

    f = open(file_name, 'wb')
    print "Downloading: %s Bytes: %s" % (file_name, file_size)

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
        print status,

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
        print "Error: Please put argument."
    print "Complet Dataset size:", (datasets_size / (1024.0 * 1024.0)), "MB"
    total_time = datetime.timedelta(seconds=time.time() - start_time)
    print("Time : " + str(total_time))  # .strftime('%H:%M:%S'))
