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


def final_train(models):
    for model in models:
        model.train(X_train, y_train)
        model.predict(X_test, y_test)
        model.compute_metrics(y_test)
        logger.debug(model.get_printable_metrics())
        with open(c.training_output_file, 'a') as f:
            f.write(("HTTPS ONLY " if only_https else "") + model.get_printable_metrics() + "\n")

    logger.info(("HTTPS ONLY\n" if only_https else "") + Model.models_metric_summary(models))


def train(model, random=False):
    model.train(X_train, y_train, random)
    model.predict(X_test, y_test)
    model.compute_metrics(y_test)
    logger.debug(model.get_printable_metrics())
    model.save(c.model_folder + model.name + ".model")
    with open(c.training_output_file, 'a') as f:
        f.write(("HTTPS ONLY " if only_https else "") + model.get_printable_metrics() + "\n")


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

    #all_models = models.keys()
    models_to_train = ['k-NN', 'Decision tree', 'Random forest', 'NB - Gaussian','AdaBoost', 'Log. Regression', 'Neural net'] #, 'SVM - SVC']

    models_to_train = ["XGBoost 1", "XGBoost 2"]

    only_https = False

    X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(c.model_folder, only_https)

    #final_train(select_models(models, models_to_train))

    #train(xgboost, random=True)

    #train(adaboost)

    #train(xgboost, False)

    #train(gnb)


    """
    import matplotlib
    from collections import Counter

    matplotlib.use('TkAgg')
    import matplotlib.pyplot as plt
    import xgboost as xgb
    import pickle

    clf = pickle.load(open(c.model_folder + xgboost.name + '.model', "rb"))

    # plot feature importance
    fig, ax = plt.subplots(figsize=(5, 10))
    ax = xgb.plot_importance(clf, ax=ax)
    #fig = ax.figure
    #fig.set_size_inches(18.5, 10.5) # h, w


    # example of how to zoomout by a factor of 0.1
    # ylim = ax.get_ylim()
    #factor = 0.1
    #new_ylim = (ylim[0] * factor + ylim[1] * factor)
    #ax.set_ylim(new_ylim)

    plt.savefig("./features_importance_xgboost.png")
    plt.show()
    """

