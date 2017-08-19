"""
1. Take data from conn_result.txt
2. normalize this data.
3. call some machine learning algorithm.
"""

import DetectionMethods
from ast import literal_eval
import numpy as np

###################
### Methof fot T-SNE array output
####################
def write_to_file(file_name, data_list):
    index = 0
    with open("Final_Experiment\\DividedData\\T-SNE_data_model\\" + file_name, 'w') as f:
        for dataline in data_list:
            try:
                label = int(dataline)
                f.write(str(label) + "\n")
            except:
                f.write(str(list(dataline)) + "\n")
            index += 1
    f.close()
    print file_name,"written lines:", index





def get_column(matrix, i):
    return [row[i] for row in matrix]


def set_column(matrix, i):
    for row in range(3):
        matrix[row * 3 + i - 1] = 0


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


def read_res(path):
    train_data = []
    train_labels = []

    test_data = []
    test_labels = []

    malware_conn = 0
    normal_conn = 0
    threshold = 1600
    # threshold = 600
    # [0] - index
    # [24] - label
    index = 0
    with open(path) as f:
        for line in f:
            split = line.split('	')
            temp = []
            if index < threshold:
                for i in range(1, len(split)-1):
                    temp.append(float(split[i]))
                train_data.append(temp)
                if 'MALWARE' in split[24]:
                    train_labels.append(1)
                    malware_conn += 1
                else:
                    train_labels.append(0)
                    normal_conn += 1
            else:
                for i in range(1, len(split)-1):
                    temp.append(float(split[i]))
                test_data.append(temp)
                if 'MALWARE' in split[24]:
                    test_labels.append(1)
                    malware_conn += 1
                else:
                    test_labels.append(0)
                    normal_conn += 1

            index += 1

    f.close()

    # print "number of malware conn:", malware_conn
    # print "number of normal conn:", normal_conn

    return train_data, train_labels, test_data, test_labels


def main(path):

    train_data, train_labels, test_data, test_labels = read_res(path)
    norm_train_data = normalize_data(train_data)
    norm_test_data = normalize_data(test_data)

    return norm_train_data, train_labels, norm_test_data, test_labels


def read_res2(path, file_name):
    data = []
    labels = []
    # [0] - index
    # [24] - label
    index = 0
    with open(path + file_name) as f:
        for line in f:
            split = line.split('	')
            temp = []
            label = split[29]
            started_index = 2
            end_index = len(split) -1
            # started_index = 22
            # end_index = len(split) -1
            if 'MALWARE' in label:
                for i in range(started_index, end_index):
                    temp.append(float(split[i]))
                data.append(temp)
                labels.append(1)
            if 'NORMAL' in label:
                for i in range(started_index, end_index):
                    temp.append(float(split[i]))
                data.append(temp)
                labels.append(0)
            index += 1
    f.close()
    print "number of lines:", index
    return data, labels


def main2(path, file_name):
    data, labels = read_res2(path, file_name)
    norm_data = normalize_data(data)
    return norm_data, labels

"""
Function for version 1
"""
def get_data_from_file(path, file_name):
    data = []
    with open(path + file_name) as f:
        for line in f:
            # data.append(map(float, literal_eval(line)))
            temp = map(float, literal_eval(line))
            features = [
                        temp[0],
                        temp[1],
                        temp[2],
                        temp[3],
                        temp[4],
                        temp[5],
                        temp[6],
                        temp[7],
                        temp[8],
                        temp[9],
                        temp[10],
                        # temp[11],
                        temp[12],
                        temp[13],
                        temp[14],
                        temp[15],
                        temp[16], #
                        temp[17],
                        temp[18],
                        temp[19],
                        temp[20],
                        temp[21],
                        temp[22],
                        temp[23],
                        temp[24],
                        temp[25],
                        temp[26],
                        # temp[27]
            ]
            # features = [
                # temp[0],
                # temp[1],
                # temp[2],
                # temp[3],
                # temp[4],
                # temp[5],

            # ]
            data.append(features)
    return data


def get_labels_from_file(path, file_name):
    labels = []
    with open(path + file_name) as f:
        for line in f:
            labels.append(int(line.rstrip()))
    return labels


def get_all_data(path_to_folder):
    X_train = get_data_from_file(path_to_folder, "X_train.txt")
    X_test = get_data_from_file(path_to_folder, "X_test.txt")
    y_train = get_labels_from_file(path_to_folder, "y_train.txt")
    y_test = get_labels_from_file(path_to_folder, "y_test.txt")
    return X_train, X_test, y_train, y_test