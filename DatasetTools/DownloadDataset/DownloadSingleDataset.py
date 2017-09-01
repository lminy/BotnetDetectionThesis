"""
Download all datasets which have bro folder.
USAGE:
python DownloadDatasets.py https://mcfp.felk.cvut.cz/publicDatasets/
"""

import sys
from bs4 import BeautifulSoup
import requests
import urllib2
import os
import shutil


def find_files(url):
    # url = "https://mcfp.felk.cvut.cz/publicDatasets/"
    soup = BeautifulSoup(requests.get(url).text, "lxml")
    hrefs = []
    for a in soup.find_all('a'):
        try:
            # print a['href']
            hrefs.append(a['href'])
        except:
            pass
    # print hrefs
    return hrefs


def save_manager(url, dataset_name):

    directiry_name = "/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/suricata/" + dataset_name


    if os.path.exists(directiry_name):
        shutil.rmtree(directiry_name)
    os.makedirs(directiry_name)

    # Bro
    folder_path = directiry_name + "/bro/"
    os.makedirs(folder_path)

    file_sizes = 0
    bro = find_files(url + 'bro/')
    for i in range(len(bro)):
        if '.log' in bro[i]:
            file_sizes += save_file2(url, folder_path + bro[i], bro[i], 'bro')

    # Suricata
    folder_path = directiry_name + "/suricata/"
    os.makedirs(folder_path)

    file_sizes = 0
    bro = find_files(url + 'suricata/')
    for i in range(len(bro)):
        if '.log' in bro[i] or '.json' in bro[i]:
            file_sizes += save_file2(url, folder_path + bro[i], bro[i], 'suricata')
    return file_sizes


def save_file2(dataset_url, file_name, bro_log, bro_or_suricata_folder):
    print bro_log, "is downloading..."
    file_size = 0
    u = urllib2.urlopen(dataset_url + bro_or_suricata_folder + '/' + bro_log)
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

def get_dataset_name_from_url(url):
    names = url.split('/')
    names.pop()
    return names.pop()


if __name__ == '__main__':
    datasets_size = 0
    if len(sys.argv) == 2:
        url = sys.argv[1]
        datasets_size += save_manager(url, get_dataset_name_from_url(url))
        # find_files(url+'CTU-Malware-Capture-Botnet-31/')
    print "Complet Dataset size:", (datasets_size / (1024.0 * 1024.0)), "MB"
