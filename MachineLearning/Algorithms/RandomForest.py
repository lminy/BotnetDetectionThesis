"""
https://github.com/frenky-strasak/My_bachelor_thesis
"""

import Get_normalize_data
import DetectionMethods
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier

##################
## Best Result:  0.941041127409
##################


"""
Read data model 1
"""
# final_path = "Final_Experiment\\DividedData\\" + "cert_data_model\\"
# final_path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/"
final_path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/2017_08_25/"

X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(final_path)

"""
Define model
"""
# model = RandomForestClassifier()
model = RandomForestClassifier(n_estimators=500, oob_score='TRUE')

"""
Crossvalidation
"""
DetectionMethods.detect_with_cross_validation(model, X_train, y_train)

"""
Detecting
"""
model.fit(X_train, y_train)
DetectionMethods.detect(model, X_test, y_test)