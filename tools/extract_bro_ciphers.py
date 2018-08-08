import os
import subprocess

datasets_folder = "/mnt/hgfs/datasets"

for dataset_name in os.listdir(datasets_folder):
    if dataset_name.startswith("."):
        continue
    for filename in os.listdir(datasets_folder + dataset_name):
        if filename.endswith('.pcap'):
            pcap_fullpath = datasets_folder + dataset_name + "/" + filename
            print("Extracting ciphers for {}...".format(pcap_fullpath))
            working_dir = datasets_folder + dataset_name + "/bro_ciphers/"
            os.mkdir(datasets_folder + dataset_name + "/bro_ciphers/")

            subprocess.Popen(["bro", "-C", "-r", "../"+filename, "-b", "base/protocols/ssl", "site/tls_finger"], cwd=working_dir).wait()