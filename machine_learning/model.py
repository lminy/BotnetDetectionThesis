from collections import OrderedDict
from sklearn.model_selection import RandomizedSearchCV, GridSearchCV
import main_tools
import math
import time
import pickle

from logger import get_logger
logger = get_logger("debug", True)


class Model(object):

    def __init__(self, name, classifier, param_grid=None):
        self.classifier = classifier
        self.name = name
        self.param_grid = param_grid

        self.tn = self.fp = self.fn = self.tp = -1
        self.metrics = OrderedDict()

        self.training_error = None
        self.is_trained = False

        self.score = None
        self.y_pred = None

    def train(self, X_train, y_train, random=False):
        if self.param_grid is not None and random is False:
            self.classifier = GridSearchCV(self.classifier, self.param_grid, cv=10, scoring='precision', n_jobs=-1)  # Do a 10-fold cross validation
        elif self.param_grid is not None and random is True:
            self.classifier = RandomizedSearchCV(self.classifier, param_distributions=self.param_grid,
                                                 n_iter=10, scoring='precision',
                                                 n_jobs=-1, cv=10, verbose=3, random_state=1001)

        logger.info('Training classifier {}'.format(self.name))
        main_tools.benchmark(self.classifier.fit, X_train, y_train) # fit the classifier with data
        logger.info('Trained classifier {}'.format(self.name))
        self.training_error = self.classifier.score(X_train, y_train)

        if self.param_grid is not None:
            logger.debug("Grid search best score = {}".format(self.classifier.best_score_))
            logger.debug("Grid search best estimator = {}".format(self.classifier.best_estimator_))
            logger.debug("Grid search cv results = {}".format(self.classifier.cv_results_))
        else:
            logger.debug("Model parameters = {}".format(self.classifier.get_params()))
        self.is_trained = True

    def predict(self, X_test, y_test):
        if not self.is_trained:
            raise Exception('Model not trained, please run train()')

        self.score = self.classifier.score(X_test, y_test)
        self.y_pred = [round(value) for value in self.classifier.predict(X_test)]	# Call predict on the estimator (with the best found parameters if Grid search).
        # Round is there is we have probabilities (like with XGBoost)

    def compute_metrics(self, y_test):
        if self.y_pred is None:
            raise Exception('No prediction found, please run predict()')

        from sklearn import metrics
        tn, fp, fn, tp = metrics.confusion_matrix(y_test, self.y_pred, labels=[0,1]).ravel()
        self.tn, self.fp, self.fn, self.tp = tn, fp, fn, tp

        logger.debug("tn={}, fp={}, fn={}, tp={}".format(tn, fp, fn, tp))

        tpr = -1 if tp <= 0 else float(tp) / (tp + fn)
        self.metrics["TPR"] = tpr  # True Positive Rate

        tnr = -1 if tn <= 0 else float(tn) / (fp + tn)
        self.metrics["TNR"] = tnr  # True Negative Rate

        fpr = -1 if tn <= 0 else float(fp) / (fp + tn)
        self.metrics["FPR"] = fpr  # False Positive Rate

        #fdr = -1 if tp <= 0 else float(fp) / (fp + tp)
        #self.metrics["FDR"] = fdr  # False Discovery Rate

        accuracy = -1 if tp <= 0 or tn <= 0 else float(tp + tn) / (tp + tn + fp + fn)
        self.metrics["Acc"] = accuracy

        error_rate = -1 if tp <= 0 or tn <= 0 else float(fp + fn) / (tp + fn + fp + tn)
        self.metrics["Err"] = error_rate

        precision = -1 if tp <= 0 else float(tp) / (tp + fp)
        self.metrics["Pre"] = precision

        f_measure = -1 if precision <= 0 else float(2 * precision * tpr) / (precision + tpr)
        self.metrics["F-M"] = f_measure

        mcc = -1 if tp <= 0 or tn <= 0 else float(tp * tn - fp * fn) / \
             math.sqrt(float(tp + fn) * (tp + fp) * (tn + fp) * (tn + fn))
        self.metrics["MCC"] = mcc  # Matthew Correlation Coefficient

        roc_fpr, roc_tpr, thresholds = metrics.roc_curve(y_test, self.y_pred)
        self.metrics["AUC"] = metrics.auc(roc_fpr, roc_tpr)

    def get_printable_metrics(self):
        if len(self.metrics) == 0:
            raise Exception('No metrics found, please run compute_metrics()')

        """
        from prettytable import PrettyTable
        import operator

        headers = ['Model', 'Best score']
        headers += self.metrics.keys()

        table = PrettyTable(headers)
        content = [self.name, self.score]
        content += [round(float(m), 3) for m in self.metrics.values()]
        table.add_row(content)

        return table.get_string(sort_key=operator.itemgetter(2, 1), sortby="Best score", reversesort=True)
        """

        headers = ['Exec time', 'Model', 'Best score']
        headers += self.metrics.keys()
        values = time.strftime("%Y-%m-%d_%H-%M-%S") + "\t" + "\t".join([self.name, str(self.score)] + map(str, self.metrics.values()))
        return "\t".join(headers) + "\n" + values



    @staticmethod
    def models_metric_summary(models):
        #from prettytable import PrettyTable
        #import operator

        headers = ['Model', 'Best score']
        headers += models[0].metrics.keys()
        """
        table = PrettyTable(headers)

        for model in models:
            if len(model.metrics) == 0:
                raise Exception('No metrics found for model "{}", please run compute_metrics()'.format(model.name))
            content = [model.name, model.score]
            content += [round(float(m), 3) for m in model.metrics.values()]
            table.add_row(content)

        return table.get_string(sort_key=operator.itemgetter(2, 1), sortby="Best score", reversesort=True)
        """

        values = ""
        for model in models:
            if len(model.metrics) == 0:
                raise Exception('No metrics found for model "{}", please run compute_metrics()'.format(model.name))

            values += "\t".join([model.name, str(model.score)] + map(str,model.metrics.values())) + "\n"
        return "\t".join(headers) + "\n" + values

    def save(self, filename):
        logger.info("Saving model to {}...".format(filename))
        pickle.dump(self.classifier, open(filename, "wb"))
        logger.info("Model saved to {}!".format(filename))

    def load(self, filename):
        logger.info("Loading model from {}...".format(filename))
        self.classifier = pickle.load(open(filename, "rb"))
        logger.info("Model loaded from {}!".format(filename))

