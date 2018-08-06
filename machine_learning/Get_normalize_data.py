
import csv
import config as c

# TODO : transform in pandas
#X = pd.read_csv(filename)
#if only_https:
#    X.drop(X.columns[range(41, 63 + 1)], axis=1, inplace=True)


def read_features(filename, only_https=False):
    X = list()
    with open(filename, 'r') as csvfile:
        csvreader = csv.reader(csvfile, lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        for row in csvreader:
            if only_https:
                X.append(row[0:41])  # Only read HTTPS features
            else:
                X.append(row)
    return X


def read_labels(filename):
    with open(filename, 'r') as csvfile:
        csvreader = csv.reader(csvfile, lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        y = csvreader.next()
    return y


def get_all_data(models_folder):
    X_train = read_features(models_folder + "X_train.csv")
    X_test = read_features(models_folder + "X_test.csv")
    y_train = read_labels(models_folder + "y_train.csv")
    y_test = read_labels(models_folder + "y_test.csv")
    return np.array(X_train), np.array(X_test), np.array(y_train), np.array(y_test)
    # return X_train, X_test, y_train, y_test




import csv
import numpy as np
import pandas as pd

X = pd.read_csv(filename)
if only_https:
    X.drop(X.columns[range(41, 63 + 1)], axis=1, inplace=True)


def read_features(filename, only_https=False):

    X = pd.read_csv(filename)
    print(X.head(5))

    #if only_https:
    #    X.append(row[0:41])  # Only read HTTPS features
    #else:
    #    X.append(row)
    return X

read_

def read_labels(filename):
    with open(filename, 'r') as csvfile:
        csvreader = csv.reader(csvfile, lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        y = csvreader.next()
    return y


def get_all_data(models_folder, only_https=False):
    X_train = read_features(models_folder + "X_train.csv", only_https)
    X_test = read_features(models_folder + "X_test.csv", only_https)
    y_train = read_labels(models_folder + "y_train.csv")
    y_test = read_labels(models_folder + "y_test.csv")
    return np.array(X_train), np.array(X_test), np.array(y_train), np.array(y_test)
    #return X_train, X_test, y_train, y_test