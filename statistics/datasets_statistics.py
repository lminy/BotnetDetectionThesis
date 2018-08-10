import os
import sys
sys.path.insert(0, os.environ['HOME'] + '/BotnetDetectionThesis/')
import config as c


def get_size_folder(start_path = '.'):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size

# https://stackoverflow.com/a/1094933
def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def compute_malware_normal_packets(path_conn_label):
    normals = 0
    malwares = 0
    with open(path_conn_label) as f:
        for line in f:
            if line[0] == '#':
                continue
            split_conn_line = line.split('\t')

            if len(split_conn_line) < 22:
                continue

            label = split_conn_line[21]

            if 'From-Normal' in label:
                normals += 1
            elif 'From-Botnet' in label:
                malwares += 1

    return (normals, malwares)


size_normal_dataset = 0
size_ctu13_malware_dataset = 0
size_other_malware_dataset = 0

normal_dataset_normal_packets = 0
ctu13_malware_dataset_normal_packets = 0
other_malware_dataset_normal_packets = 0

normal_dataset_malware_packets = 0
ctu13_malware_dataset_malware_packets = 0
other_malware_dataset_malware_packets = 0


index = 0
for sub_set in os.listdir(c.datasets_folder):
    if sub_set.startswith(".") or not os.path.exists(c.datasets_folder + sub_set + '/bro/ssl.log'):
        continue
    print "--------------------------------------------------------"
    print "-------- #" + str(index) + " " + sub_set
    print "--------------------------------------------------------"


    dataset_bro_folder = c.datasets_folder + sub_set + '/bro/'
    dataset_size = get_size_folder(dataset_bro_folder)
    print "Size of dataset : " + str(sizeof_fmt(dataset_size))
    index += 1

    normals, malwares = compute_malware_normal_packets(dataset_bro_folder + 'conn_label.log')

    if sub_set.startswith("CTU-Normal-"):
        size_normal_dataset += dataset_size
        normal_dataset_normal_packets += normals
        normal_dataset_malware_packets += malwares
    elif sub_set.startswith("CTU-Malware-Capture-Botnet-") and 42 <= int(sub_set.split('-')[4]) <= 54:
        size_ctu13_malware_dataset += dataset_size
        ctu13_malware_dataset_normal_packets += normals
        ctu13_malware_dataset_malware_packets += malwares
    elif sub_set.startswith("CTU-Malware-Capture-Botnet-"):
        size_other_malware_dataset += dataset_size
        other_malware_dataset_normal_packets += normals
        other_malware_dataset_malware_packets +=malwares


    print "Normal packets: " + str(normals)
    print "Malware packets : " + str(malwares)



print "\n\n============================"
print "Size normal datasets : " + str(sizeof_fmt(size_normal_dataset))
print "\t>>> Normal packets : " + str(normal_dataset_normal_packets)
print "\t>>> Malware packets : " + str(normal_dataset_malware_packets)
print "Size CTU-13 malware datasets : " + str(sizeof_fmt(size_ctu13_malware_dataset))
print "\t>>> Normal packets : " + str(ctu13_malware_dataset_normal_packets)
print "\t>>> Malware packets : " + str(ctu13_malware_dataset_malware_packets)
print "Size other malware datasets : " + str(sizeof_fmt(size_other_malware_dataset))
print "\t>>> Normal packets : " + str(other_malware_dataset_normal_packets)
print "\t>>> Malware packets : " + str(other_malware_dataset_malware_packets)
print "\n------------------"
print "  TOTAL Datasets"
print "------------------"
print "Total Size : " + str(sizeof_fmt(size_normal_dataset + size_ctu13_malware_dataset + size_other_malware_dataset))
print "Total normal packets : " + str(normal_dataset_normal_packets + ctu13_malware_dataset_normal_packets + other_malware_dataset_normal_packets)
print "Total malwares packets : " + str(normal_dataset_malware_packets + ctu13_malware_dataset_malware_packets + other_malware_dataset_malware_packets)



