
import csv
import config as c

def read_features(filename):
    X = list()
    with open(filename, 'r') as csvfile:
        csvreader = csv.reader(csvfile, lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        for row in csvreader:
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
    return X_train, X_test, y_train, y_test