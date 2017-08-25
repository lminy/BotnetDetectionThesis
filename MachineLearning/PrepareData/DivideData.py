"""
!!! Dividing data for NON-BALANCED data !!!
Divide data from conn_result.txt to payload data (without conn_tuple) and save again.
It divides normal data to training and testing data and then same with Malware.
"""
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle

def normalize_data(data):
    for i in range(0, len(data[0])):
        max = 0
        for j in range(len(data)):
            if max < data[j][i]:
                max = data[j][i]
        if max != 0:
            for j in range(len(data)):
                if data[j][i] != -1:
                    data[j][i] = data[j][i] / float(max)
    return data


def write_to_file(file_name, data_list):
    index = 0
    with open(dst_path + file_name, 'w') as f:
        for dataline in data_list:
            f.write(str(dataline) + "\n")
            index += 1
    f.close()
    print file_name, "written lines:", index


"""
----------------------------------------------
--------- Beginning of code ------------------
----------------------------------------------
"""
# Destination path.
source_path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/PrepareData/2017_08_25/conn_result_2017-08-25_09-26.txt"
dst_path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/2017_08_25/"

# Load all file to array.
all_tuples = []
try:
    with open(source_path) as f:
    # with open("DividedData\\all_features_2\\malware_connections.txt") as f:
        for line in f:
            all_tuples.append(line)
    f.close()
except:
    print "Error: No file is avaible."


X = []
y = []

malwares = 0
normals = 0
for line in all_tuples:
    split = line.split('	')
    label = split[29] # connection data model
    # label = split[7] # certificate data model

    # print label
    number_label = -1

    check_value = 0
    if 'MALWARE' in label:
        check_value += 1
        number_label = 1
        malwares += 1

    if "NORMAL" in label:
        check_value += 1
        number_label = 0
        normals += 1

    temp = []
    for i in range(1, 29):  # 29
        temp.append(float(split[i]))
    X.append(temp)
    y.append(number_label)

    if number_label == -1:
        print "ERROR: label is -1. Program is terminated."
        break

    if check_value == 2:
        print "Error: more labels."
        print "Program is terminated."
        break


# normalize X
norm_X = normalize_data(X)

print "Malwares:", malwares
print "Normals:", normals


# Divide normX and y to malware and normal.
norm_X_malware = []
y_malware = []
norm_X_normal = []
y_normal = []
for i in range(0, len(y)):
    if y[i] == 1:
        norm_X_malware.append(norm_X[i])
        y_malware.append(y[i])
    else:
        norm_X_normal.append(norm_X[i])
        y_normal.append(y[i])




# split data by sklearn library
# Split Malware data.
malware_X_train, malware_X_test, malware_y_train, malware_y_test = train_test_split(norm_X_malware, y_malware, test_size=.13, random_state=35)
# Split Normal data.
normal_X_train, normal_X_test, normal_y_train, normal_y_test = train_test_split(norm_X_normal, y_normal, test_size=.78, random_state=42)


# Merge normal and malware train data
X_train = malware_X_train + normal_X_train
y_train = malware_y_train + normal_y_train
# Merge normal and malware test data
X_test = malware_X_test + normal_X_test
y_test = malware_y_test + normal_y_test


X_train, y_train = shuffle(X_train, y_train, random_state=43)
X_test, y_test = shuffle(X_test, y_test, random_state=101)




# Write train data
write_to_file('X_train.txt', X_train)
write_to_file('y_train.txt', y_train)

# Write test data
write_to_file('X_test.txt', X_test)
write_to_file('y_test.txt', y_test)

