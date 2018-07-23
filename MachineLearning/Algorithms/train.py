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

    logger.info(Model.models_metric_summary(models))


if __name__ == '__main__':
    logger = get_logger("debug")

    X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(c.model_folder)

    models = list()

    #k-NN Classifier
    name = "k-NN"
    classifier = KNeighborsClassifier(weights='uniform')
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
    classifier = RandomForestClassifier()
    d_range = list(range(1, 31)) # list of parameter values to test
    #s_range = list(range(2, 10))
    param_grid = dict(max_depth=d_range)#, min_samples_split=s_range)
    models.append(Model(name, classifier, param_grid))

    #Naive Bayes
    name = "NB - Gaussian"
    classifier = GaussianNB()
    models.append(Model(name, classifier))


    #SVM - Support Vector Machine
    name = "SVM - SVC"
    classifier = svm.SVC()
    C_range = np.logspace(-2, 10, 13)
    #print(C_range)
    gamma_range = np.logspace(-9, 3, 13)
    #print(gamma_range)
    param_grid = dict(gamma=gamma_range, C=C_range)
    models.append(Model(name, classifier, param_grid))

    #AdaBoost
    name = "AdaBoost"
    classifier = AdaBoostClassifier(n_estimators=100)
    models.append(Model(name, classifier))

    #Logistic Regression
    name = "Log. Regression"
    classifier = LogisticRegression()
    models.append(Model(name, classifier))

    #Neural networks
    from sklearn.neural_network import MLPClassifier
    name = "Neural net"
    #classifier = MLPClassifier(alpha=1)
    classifier = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
    models.append(Model(name, classifier))


    name = "SVM - Linear"
    classifier = svm.LinearSVC()
    C_range = range(170,230,5)
    C_range = range(1,200,10)
    param_grid = dict(C=C_range)
    models.append(Model(name, classifier, param_grid))
    
    name = "NB - Multinomial"
    classifier = MultinomialNB()
    models.append(Model(name, classifier))
    
    name = "NB - Bernoulli"
    classifier = BernoulliNB()
    models.append(Model(name, classifier))

    #all_models = models.keys()
    models_to_train = ['k-NN', 'Decision tree', 'Random forest', 'NB - Gaussian', 'SVM - SVC',
                       'AdaBoost', 'Log. Regression', 'Neural net']

    final_train(select_models(models, models_to_train))


