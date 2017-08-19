"""
https://github.com/frenky-strasak/My_bachelor_thesis
"""

"""
python Learn_Manager.py c:\Users\frenk\Documents\Skola\Bachelor_thesis\My_bachelor_thesis\MachineLearning\Experiment_results\2017_04_20_2127conn\
"""

import Get_normalize_data
import DetectionMethods
import sys
from sklearn import svm

# path = sys.argv[1]
# final_path = "Final_Experiment\\DividedData\\" + "all_features_2\\"
# norm_data_N, labels_N = Get_normalize_data.main2(final_path, "normal_connections.txt")
# norm_data_M, labels_M = Get_normalize_data.main2(final_path, "malware_connections.txt")
#
# norm_data = norm_data_N + norm_data_M
# labels = labels_N + labels_M
#
# print "data:", len(norm_data)
# print "labels:", len(labels)
# print len(norm_data[0])


# final_path = "Final_Experiment\\DividedData\\" + "cert_data_model\\"
final_path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/"

X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(final_path)

kernels = ['linear', 'poly', 'rbf', 'sigmoid']
svm_C = 110
svm_gamma = 0.1
index = 2

# 0.74583093732 - C=110 - g= 0.1 k=rbf


# CrossValidation
clf = svm.SVC(kernel=kernels[index], C=svm_C, gamma=svm_gamma)
DetectionMethods.detect_with_cross_validation(clf, X_train, y_train)


# detect
clf = svm.SVC(kernel=kernels[index], C=svm_C, gamma=svm_gamma)
clf.fit(X_train, y_train)
DetectionMethods.detect(clf, X_test, y_test)




