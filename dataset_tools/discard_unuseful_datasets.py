import os
import shutil
import json
import config as c

with open('./infected_ips.json', 'r') as f:
    infected_ips = json.load(f)

with open('./normal_ips.json', 'r') as f:
    normal_ips = json.load(f)

index = 0
for sub_set in os.listdir(c.datasets_folder_general):
    if sub_set.startswith(".") or not os.path.exists(datasets_folder + sub_set + '/bro/ssl.log'):
        continue

    dataset_folder = c.datasets_folder_general + sub_set

    index += 1

    dataset_number = int(sub_set.split('-')[4])
    if sub_set.startswith("CTU-Malware-Capture-Botnet-") and (dataset_number <= 42 or dataset_number >= 54):
        print("========================================================")
        print("======== #" + str(index) + " " + sub_set)
        print("========================================================")
        if len(infected_ips[sub_set][0]) == 0 and \
            len(normal_ips[sub_set][0]) == 0:
            print("Moving dataset {} ({}) to {}".format(sub_set, dataset_folder, folder_other_datasets))
            shutil.move(dataset_folder, c.datasets_discarded_folder)