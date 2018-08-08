import os
import sys
sys.path.insert(0, os.environ['HOME'] + '/BotnetDetectionThesis/')


from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.naive_bayes import BernoulliNB
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn import svm
from sklearn import tree

import numpy as np
import Get_normalize_data
import config as c
from logger import get_logger
from model import Model


def select_models(models, models_name):
    return [m for m in models if m.name in models_name]


def final_train(models, set_name):
    with open(c.training_output_file, 'a') as f:
        f.write("Features set : " + set_name + "\n")
        for model in models:
            model.train(X_train, y_train)
            model.predict(X_test, y_test)
            model.compute_metrics(y_test)
            logger.debug(model.get_printable_metrics())
            with open(c.training_output_file, 'a') as f:
                f.write(model.get_printable_metrics() + "\n")

    logger.info("Features set : " + set_name)
    logger.info(Model.models_metric_summary(models))


def train(model, set_name, random=False):
    model.train(X_train, y_train, random)
    model.predict(X_test, y_test)
    model.compute_metrics(y_test)
    logger.debug(model.get_printable_metrics())
    model.save(c.model_folder + model.name + ".model")
    with open(c.training_output_file, 'a') as f:
        f.write("Features set : " + set_name + "\n")
        f.write(model.get_printable_metrics() + "\n")
    logger.info("Features set : " + set_name)
    logger.info(model.get_printable_metrics())


if __name__ == '__main__':
    logger = get_logger("debug", append=True)

    models = list()

    #k-NN Classifier
    name = "k-NN"
    classifier = KNeighborsClassifier(weights='uniform', n_jobs=-1)
    k_range = list(range(1, 31)) # list of parameter values to test
    param_grid = dict(n_neighbors=k_range)
    models.append(Model(name, classifier, param_grid))

    #Decision Tree
    name = "Decision tree"
    classifier = tree.DecisionTreeClassifier(criterion='entropy')
    d_range = list(range(1, 31)) # list of parameter values to test
    #s_range = list(range(2, 10))
    param_grid = dict(max_depth=d_range)#, min_samples_split=s_range)
    models.append(Model(name, classifier, param_grid))

    #Random Forest
    name = "Random forest"
    classifier = RandomForestClassifier(n_jobs=-1)
    d_range = list(range(1, 31)) # list of parameter values to test
    #s_range = list(range(2, 10))
    param_grid = dict(max_depth=d_range)#, min_samples_split=s_range)
    models.append(Model(name, classifier, param_grid))

    #Naive Bayes
    name = "NB - Gaussian"
    classifier = GaussianNB()
    gnb = Model(name, classifier)
    models.append(gnb)

    #AdaBoost
    name = "AdaBoost"
    classifier = AdaBoostClassifier(n_estimators=100)
    adaboost = Model(name, classifier)
    models.append(adaboost)

    #Logistic Regression
    name = "Log. Regression"
    classifier = LogisticRegression(n_jobs=-1)
    models.append(Model(name, classifier))

    #Neural networks
    from sklearn.neural_network import MLPClassifier
    name = "Neural net"
    #classifier = MLPClassifier(alpha=1)
    #classifier = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
    classifier = MLPClassifier(solver='adam', alpha=1e-5, random_state=1) # from Strasak thesis
    nn = Model(name, classifier)
    models.append(nn)

    # SVM - Support Vector Machine
    name = "SVM - SVC"
    classifier = svm.SVC()
    C_range = np.logspace(-2, 10, 13)
    # print(C_range)
    gamma_range = np.logspace(-9, 3, 13)
    # print(gamma_range)
    param_grid = dict(gamma=gamma_range, C=C_range)
    models.append(Model(name, classifier, param_grid))

    name = "SVM - Linear"
    classifier = svm.LinearSVC()
    #C_range = range(1,200,50)
    C_range = range(1,200,50)
    param_grid = dict(C=C_range)
    models.append(Model(name, classifier, param_grid))
    
    name = "NB - Multinomial"
    classifier = MultinomialNB()
    models.append(Model(name, classifier))
    
    name = "NB - Bernoulli"
    classifier = BernoulliNB()
    models.append(Model(name, classifier))

    name = "XGBoost 1"
    classifier = XGBClassifier(
        learning_rate =0.1,
        n_estimators=1000,
        max_depth=10,
        min_child_weight=1,
        gamma=0,
        subsample=0.8,
        colsample_bytree=0.8,
        objective= 'binary:logistic',
        nthread=4,
        scale_pos_weight=1,
        seed=3)
    models.append(Model(name,classifier))

    name = "XGBoost 2"
    classifier = XGBClassifier(
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
    models.append(Model(name, classifier))

    name = "XGBoost"
    classifier = XGBClassifier(
        learning_rate=0.1,
        n_estimators=1000,
        objective='binary:logistic',
        nthread=4,
        scale_pos_weight=1,
        seed=27)
    param_grid = {
        'min_child_weight': [1, 5, 10],
        'gamma': [0.5, 1, 1.5, 2, 5],
        'subsample': [0.6, 0.8, 1.0],
        'colsample_bytree': [0.6, 0.8, 1.0],
        'max_depth': [3, 4, 5]
    }
    xgboost = Model(name, classifier, param_grid)
    models.append(xgboost)

    name = "XGBoostBest"
    classifier = XGBClassifier(base_score=0.5, booster='gbtree', colsample_bylevel=1,
                          colsample_bytree=0.6, gamma=0.5, learning_rate=0.1,
                          max_delta_step=0, max_depth=5, min_child_weight=1, missing=None,
                          n_estimators=1000, n_jobs=1, nthread=4, objective='binary:logistic',
                          random_state=0, reg_alpha=0, reg_lambda=1, scale_pos_weight=1,
                          seed=27, silent=True, subsample=0.8)
    xgboost_best = Model(name, classifier)


    #all_models = models.keys()
    models_to_train = ['XGBoost', 'k-NN', 'Decision tree', 'Random forest', 'NB - Gaussian','AdaBoost', 'Log. Regression', 'Neural net'] #, 'SVM - SVC']

    # set_name can be: all, dns, https, reduced, reduced_30, reduced_40, enhanced_30
    set_name = "enhanced_30"
    X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(c.model_folder, set_name)

    final_train(select_models(models, set_name, models_to_train))

    #train(xgboost, set_name, random=True)

    #train(xgboost_best, set_name)

    #train(xgboost, set_name, False)

    #train(gnb, set_name)


