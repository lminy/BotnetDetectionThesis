"""
https://github.com/frenky-strasak/My_bachelor_thesis
"""

import Get_normalize_data
import DetectionMethods
from xgboost import XGBClassifier
import numpy as np

##################
## Best Result: 0.909404659189 with datamodel 2
##################


# final_path = "Final_Experiment\\DividedData\\" + "data_model_1\\"
final_path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/2017_08_25/"

"""
Load Data
"""
X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(final_path)

np_X_train, np_X_test, np_y_train, np_y_test = np.array(X_train), np.array(X_test), np.array(y_train), np.array(y_test)

"""
Define model
"""
# XGBoost 1
# binary:logistic - logistic regression for binary classification, output probability
# model = XGBClassifier(learning_rate =0.1,
# n_estimators=1000,
# max_depth=10,
# min_child_weight=1,
# gamma=0,
# subsample=0.8,
# colsample_bytree=0.8,
# objective= 'binary:logistic',
# nthread=4,
# scale_pos_weight=1,
# seed=3


# XGBoost 2
# title = "Learning Curves ( XGBoost s)"
model = XGBClassifier(
    learning_rate=0.1,
    n_estimators=1000,
    max_depth=3,
    min_child_weight=5,
    gamma=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='binary:logistic',
    nthread=4,
    scale_pos_weight=1,
    seed=27)

"""
Crossvalidation
"""
DetectionMethods.detect_with_cross_validation(model, np_X_train, np_y_train)

"""
Detect model
"""
# model = XGBClassifier()
model.fit(np_X_train, np_y_train)
DetectionMethods.detect(model, np_X_test, np_y_test)