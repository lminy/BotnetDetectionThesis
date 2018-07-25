
import os
import json
import re
import config as c


def run(cmd):
    import subprocess
    return subprocess.check_output(cmd)

infected_ips = dict()
normal_ips = dict()


def print_ips(dataset_name=None):
    if dataset_name is None:
        print "Infected IPs : " + json.dumps(infected_ips)
        print "Normal IPs : " + json.dumps(normal_ips)
    else:
        print "Infected IPs : " + json.dumps(infected_ips[dataset_name])
        print "Normal IPs : " + json.dumps(normal_ips[dataset_name])


# Loads json files
if os.path.exists("./infected_ips.json") and os.path.exists("./normal_ips.json"):
    with open('./infected_ips.json', 'r') as f:
        infected_ips = json.load(f)

    with open('./normal_ips.json', 'r') as f:
        normal_ips = json.load(f)

    print_ips()


infected_ips_collected_by_hand = {
    "CTU-Malware-Capture-Botnet-25-1":["10.0.2.106"],
    "CTU-Malware-Capture-Botnet-25-2":["10.0.2.103"],
    "CTU-Malware-Capture-Botnet-25-3":["10.0.2.103"],
    "CTU-Malware-Capture-Botnet-25-4":["10.0.2.103"],
    "CTU-Malware-Capture-Botnet-25-5":["10.0.2.103"],
    "CTU-Malware-Capture-Botnet-25-6":["10.0.2.103"],
    "CTU-Malware-Capture-Botnet-31-1":["10.0.2.110"],
    "CTU-Malware-Capture-Botnet-69":["10.0.2.117"],
    "CTU-Malware-Capture-Botnet-78-2":["10.0.2.108"],
    "CTU-Malware-Capture-Botnet-78-1":["10.0.2.108"],
    "CTU-Malware-Capture-Botnet-83-1":["10.0.2.102"],
    "CTU-Malware-Capture-Botnet-83-2":["10.0.2.102"],
    "CTU-Malware-Capture-Botnet-90":["192.168.3.104"],
    "CTU-Malware-Capture-Botnet-261-4":['192.168.1.'+str(i) for i in range(0,256)],
    "CTU-Malware-Capture-Botnet-301-1":['192.168.1.'+str(i) for i in range(0,256)],
    "CTU-Malware-Capture-Botnet-321-1":['192.168.1.'+str(i) for i in range(0,256)],

}

infected_ips.update(infected_ips_collected_by_hand)

with open('./infected_ips.json', 'w') as f:
    f.write(json.dumps(infected_ips))


normal_ips_collected_by_hand = {
    "CTU-Malware-Capture-Botnet-25-1":[""],
    "CTU-Malware-Capture-Botnet-25-2":[""],
    "CTU-Malware-Capture-Botnet-25-3":[""],
    "CTU-Malware-Capture-Botnet-25-4":[""],
    "CTU-Malware-Capture-Botnet-25-5":[""],
    "CTU-Malware-Capture-Botnet-25-6":[""],
    "CTU-Malware-Capture-Botnet-31-1":[""],
    "CTU-Malware-Capture-Botnet-69":[""],
    "CTU-Malware-Capture-Botnet-78-1":[""],
    "CTU-Malware-Capture-Botnet-78-2":[""],
    "CTU-Malware-Capture-Botnet-83-1":[""],
    "CTU-Malware-Capture-Botnet-83-2":[""],
    "CTU-Malware-Capture-Botnet-90":[""],
    "CTU-Malware-Capture-Botnet-261-4":[""],
    "CTU-Malware-Capture-Botnet-301-1":[""],
    "CTU-Malware-Capture-Botnet-321-1":[""],
}

normal_ips.update(normal_ips_collected_by_hand)

with open('./normal_ips.json', 'w') as f:
    f.write(json.dumps(normal_ips))


index = 0
for sub_set in os.listdir(c.datasets_folder_general):
    if sub_set.startswith(".") or not os.path.exists(c.datasets_folder_general + sub_set + '/bro/ssl.log'):
        continue

    dataset_folder = c.datasets_folder_general + sub_set

    index += 1

    dataset_number = int(sub_set.split('-')[4])
    if sub_set.startswith("CTU-Malware-Capture-Botnet-") and (dataset_number <= 42 or dataset_number >= 54):
        print "========================================================"
        print "======== #" + str(index) + " " + sub_set
        print "========================================================"
        if sub_set in infected_ips:
            print "Already checked! :)"
            print_ips(sub_set)
            continue

        #print os.listdir(dataset_folder)
        for filename in os.listdir(dataset_folder):
            if "README.html" in filename:
                ips = list()

                with open(dataset_folder + "/" + filename) as f:
                    for line in f:
                        matchObj = re.match('.*Infected host: (\d+\.\d+\.\d+\.\d+).*', line)

                        if matchObj:
                            ips.append(matchObj.group(1))

                if len(ips) > 0:
                    print "IPs Found : " + str(ips)
                    infected_ips[sub_set] = ips
                    with open('./infected_ips.json', 'w') as f:
                        f.write(json.dumps(infected_ips))
                    normal_ips[sub_set] = [""]
                    with open('./normal_ips.json', 'w') as f:
                        f.write(json.dumps(normal_ips))
                else:
                    print "No match!!"
                    print "------------------------------------"
                    print "---------- Infected hosts"
                    #print run(["grep", "-i", "-C", "3", "Infected", dataset_folder + "/" + filename])
                    ips = str(raw_input())
                    infected_ips[sub_set] = ips.split(",")
                    with open('./infected_ips.json', 'w') as f:
                        f.write(json.dumps(infected_ips))

                    print "------------------------------------"
                    print "---------- Normal hosts"
                    #print run(["grep", "-i", "-C", "3", 'Normal', dataset_folder + "/" + filename])
                    ips = str(raw_input())
                    normal_ips[sub_set] = ips.split(",")
                    with open('./normal_ips.json', 'w') as f:
                        f.write(json.dumps(normal_ips))
                    break


