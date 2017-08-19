"""
Download all datasets which have bro folder.
USAGE:
python DownloadDatasets.py https://mcfp.felk.cvut.cz/publicDatasets/
"""

import sys
from bs4 import BeautifulSoup
import requests
import urllib2
import urllib
import os
import shutil
import nltk
from urllib import urlopen


# exmaple:
# https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-305-2/README.md
def get_readme_content(url_to_readme_file):
    mp3file = urllib2.urlopen(url_to_readme_file)
    readme_content = mp3file.read()
    return readme_content


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


def compute_datasets_size(url):
    dataset_names = find_files(url)
    file_sizes = 0
    for i in range(len(dataset_names)):
        if 'CTU-Malware-Capture-Botnet-' in dataset_names[i]:
            number_name = int(dataset_names[i].split('-')[4].replace('/', ''))

            if number_name < 248:
                continue

            print url + dataset_names[i]

            # Get content of the main page of dataset.
            content = find_files(url + dataset_names[i])

            # Look into open folder to files there. There are binetflow, bro, ...
            # And find the bro folder in this list.
            for j in range(len(content)):
                if 'bro' in content[j]:
                    print dataset_names[i] + content[j]
                    file_sizes += save_manager(url, dataset_names[i])
                    break

    return file_sizes


def save_manager(url, dataset_name):
    file_sizes = 0
    bro = find_files(url + dataset_name + 'bro/')
    # If the bro directory does not contain ssl.log, continue.
    if 'ssl.log' in bro:
        directiry_name = "/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset_2_malware/" + dataset_name
        if os.path.exists(directiry_name):
            shutil.rmtree(directiry_name)
        os.makedirs(directiry_name)
        folder_path = directiry_name + "/bro/"
        os.makedirs(folder_path)

        print bro

        for i in range(len(bro)):
            if '.log' in bro[i]:
                try:
                    file_sizes += save_file2(url + dataset_name, folder_path + bro[i], bro[i])
                except:
                    print "Error:", bro[i], "is not able to downloaded."
    return file_sizes


def save_file2(dataset_url, file_name, bro_log):
    print bro_log, "is downloading..."
    file_size = 0
    u = urllib2.urlopen(dataset_url + 'bro/' + bro_log)
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
    datasets_size = 0
    if len(sys.argv) == 2:
        url = sys.argv[1]
        datasets_size += compute_datasets_size(url)
        # find_files(url+'CTU-Malware-Capture-Botnet-31/')
    else:
        print "Error: Please put argument."
    print "Complet Dataset size:", (datasets_size / (1024.0 * 1024.0)), "MB"
