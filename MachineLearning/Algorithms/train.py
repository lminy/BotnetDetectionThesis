from sklearn.model_selection import GridSearchCV
from sklearn import tree
from sklearn.neighbors import KNeighborsClassifier
from sklearn import svm
from sklearn.naive_bayes import MultinomialNB
from sklearn.naive_bayes import BernoulliNB
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.linear_model import LogisticRegression

import Get_normalize_data
import time
import datetime
import numpy as np
import config as c

X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(c.model_folder)
X = X_train
y = y_train

results = dict()

def train(classifier, name, param_grid=None) :
    print "Training " + name + " classifier..."
    start_time = time.time()
    if param_grid == None :
        classifier.fit(X_train, y_train)
        results[name] = dict(model=classifier)
    else :
        grid = GridSearchCV(classifier, param_grid, cv=10, scoring='accuracy', n_jobs=2) # Do a 10-fold cross validation
        grid.fit(X, y) # fit the grid with data
        results[name] = dict(grid=grid, model=classifier)
    #total_time = datetime.datetime.fromtimestamp(time.time() - start_time)
    total_time = datetime.timedelta(seconds=time.time() - start_time)
    print("Training time : " + str(total_time))#.strftime('%H:%M:%S'))

def print_results():
    from prettytable import PrettyTable
    import operator
    from sklearn import metrics
    import math
    t = PrettyTable(
        ['Model', 'Best score', 'accuracy', 'precision', 'recall', 'F-M.', 'MCC', 'AUC'])  # 'FP', 'TN', 'FN', 'TP'])
    for clf_name, result in results.items():
        model = result['model']
        if 'grid' in result:
            grid = result['grid']
            score = grid.best_score_
            # Compute false positives and false negatives
            model.__init__(**grid.best_params_)
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            # print(result.best_estimator_)
        else:  # For non grid_search models
            # training_error = clf.score(X_train, y_train)
            score = model.score(X_test, y_test)
            y_pred = model.predict(X_test)

        fpr, tpr, thresholds = metrics.roc_curve(y_test, y_pred)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        # print(clf_name + " tn=" + str(tn) + " fp=" + str(fp) + " fn=" + str(fn) + " tp=" + str(tp))
        accuracy = float(tp + tn) / (tp + tn + fp + fn)
        precision = float(tp) / (tp + fp)
        recall = float(tp) / (tp + fn)  # a.k.a. sensitivity
        f_measure = float(2 * precision * recall) / (precision + recall)
        mcc = -1
        if fp != 0 and tp != 0 and tn != 0 and fn != 0:
            mcc = float(tp * tn - fp * fn) / math.sqrt(
                float(tp + fn) * (tp + fp) * (tn + fp) * (tn + fn))  # Matthew Correlation Coefficient
        auc = metrics.auc(fpr, tpr)
        t.add_row(
            [clf_name, round(score, 3), round(accuracy, 3), round(precision, 3), round(recall, 3), round(f_measure, 3),
             round(mcc, 3), round(auc, 3)])  # fp, tn, fn, tp])

    print(t.get_string(sort_key=operator.itemgetter(2, 1), sortby="Best score", reversesort=True))

#k-NN Classifier
name = "k-NN"
classifier = KNeighborsClassifier(weights='uniform')
k_range = list(range(1, 31)) # list of parameter values to test
param_grid = dict(n_neighbors=k_range)
train(classifier, name, param_grid)

#Decision Tree
name = "Decision tree"
classifier = tree.DecisionTreeClassifier(criterion='entropy')
d_range = list(range(1, 31)) # list of parameter values to test
#s_range = list(range(2, 10))
param_grid = dict(max_depth=d_range)#, min_samples_split=s_range)
train(classifier, name, param_grid)

#Naive Bayes
name = "NB - Gaussian"
classifier = GaussianNB()
train(classifier, name)
"""
name = "NB - Multinomial"
classifier = MultinomialNB()
train(classifier, name)

name = "NB - Bernoulli"
classifier = BernoulliNB()
train(classifier, name)
"""

#SVM - Support Vector Machine
name = "SVM - SVC"
classifier = svm.SVC()
C_range = np.logspace(-2, 10, 13)
#print(C_range)
gamma_range = np.logspace(-9, 3, 13)
#print(gamma_range)
param_grid = dict(gamma=gamma_range, C=C_range)
train(classifier, name, param_grid)

name = "SVM - Linear"
classifier = svm.LinearSVC()
C_range = range(170,230,5)
C_range = range(1,200,10)
param_grid = dict(C=C_range)
train(classifier, name, param_grid)

#Random Forest
name = "Random forest"
classifier = RandomForestClassifier()
d_range = list(range(1, 31)) # list of parameter values to test
#s_range = list(range(2, 10))
param_grid = dict(max_depth=d_range)#, min_samples_split=s_range)
train(classifier, name, param_grid)

#AdaBoost
name = "AdaBoost"
classifier = AdaBoostClassifier(n_estimators=100)
train(classifier, name)

#Logistic Regression
name = "Log. Regression"
classifier = LogisticRegression()
train(classifier, name)

#Neural networks
from sklearn.neural_network import MLPClassifier
name = "Neural net"
#classifier = MLPClassifier(alpha=1)
classifier = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
train(classifier, name)

print_results()
