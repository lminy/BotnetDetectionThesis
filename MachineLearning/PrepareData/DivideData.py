"""
Divide data from conn_result.txt to payload data (without conn_tuple) and save again
"""
from sklearn.model_selection import train_test_split


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
    with open("/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/" + file_name, 'w') as f:
        for dataline in data_list:
            f.write(str(dataline) + "\n")
            index += 1
    f.close()
    print file_name,"written lines:", index


def write_to_file_2(file_name, data_list):
    index = 0
    with open("DividedData\\features_parts\\" + file_name, 'w') as f:
        for dataline in data_list:
            f.write(str(dataline) + "\n")
            index += 1
    f.close()
    print file_name,"written lines:", index








all_tuples = []


try:
    with open("conn_result_2017_08_16_1.txt") as f:
    # with open("DividedData\\all_features_2\\malware_connections.txt") as f:
        for line in f:
            all_tuples.append(line)
    f.close()
except:
    print "No file."


X = []
y = []

malwares = 0
normals = 0
for line in all_tuples:
    split = line.split('	')
    label = split[29] # connection data model
    # label = split[7] # certificate data model

    print label
    number_label = -1

    if 'MALWARE' in label:
        number_label = 1
        malwares += 1
    if "NORMAL" in label:
        number_label = 0
        normals += 1
    if number_label == -1:
        print "ERROR: label is -1."
        break

    temp = []
    for i in range(1, 29): # 29
        temp.append(float(split[i]))
    X.append(temp)
    y.append(number_label)


# normalize X
norm_X = normalize_data(X)
print "velikost naseho krasneho celeho X je:", len(X)
print "Malwares:", malwares
print "Normals:", normals

# split data by sklearn library
X_train, X_test, y_train, y_test = train_test_split(norm_X, y, test_size=.2, random_state=35)

# Write train data
write_to_file('X_train.txt', X_train)
write_to_file('y_train.txt', y_train)

# Write test data
write_to_file('X_test.txt', X_test)
write_to_file('y_test.txt', y_test)

