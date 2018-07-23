
import os
import json

def run(cmd):
    import subprocess
    return subprocess.check_output(cmd)



infected_ips = dict()
normal_ips = dict()
datasets_folder = "/Volumes/Data/datasets/"

def print_ips():
    print "Infected IPs : " + json.dumps(infected_ips)
    print "Normal IPs : " + json.dumps(normal_ips)

# Loads json files
with open('./infected_ips.json', 'r') as f:
    infected_ips = json.load(f)

with open('./normal_ips.json', 'r') as f:
    normal_ips = json.load(f)
print_ips()


index = 0
for sub_set in os.listdir(datasets_folder):
    if sub_set.startswith(".") or not os.path.exists(datasets_folder + sub_set + '/bro/ssl.log'):
        continue

    dataset_folder = datasets_folder + sub_set

    index += 1

    dataset_number = int(sub_set.split('-')[4])
    if sub_set.startswith("CTU-Malware-Capture-Botnet-") and (dataset_number <= 42 or dataset_number >= 54):
        print "========================================================"
        print "======== #" + str(index) + " " + sub_set
        print "========================================================"
        if sub_set in infected_ips:
            print "Already checked! :)"
            print_ips()
            continue

        #print os.listdir(dataset_folder)
        for filename in os.listdir(dataset_folder):
            if "README" in filename:
                print "------------------------------------"
                print "---------- Infected hosts"
                print run(["grep", "-i", "-C", "3", "Infected", dataset_folder + "/" + filename])
                ips = str(raw_input())
                infected_ips[sub_set] = ips.split(",")
                with open('./infected_ips.json', 'w') as f:
                    f.write(json.dumps(infected_ips))

                print "------------------------------------"
                print "---------- Normal hosts"
                print run(["grep", "-i", "-C", "3", 'Normal', dataset_folder + "/" + filename])
                ips = str(raw_input())
                normal_ips[sub_set] = ips.split(",")
                with open('./normal_ips.json', 'w') as f:
                    f.write(json.dumps(normal_ips))
                break

