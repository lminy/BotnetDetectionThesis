import Get_normalize_data
import config as c
from logger import get_logger

# https://chrisalbon.com/machine_learning/feature_selection/anova_f-value_for_feature_selection/


def compare_quantitative_features(X, y): # ANOVA F-value
    from sklearn.feature_selection import SelectKBest
    from sklearn.feature_selection import f_classif

    # Create an SelectKBest object to select features with two best ANOVA F-Values
    fvalue_selector = SelectKBest(f_classif, k=10)

    # Apply the SelectKBest object to the features and target
    X_kbest = fvalue_selector.fit_transform(X, y)

    print fvalue_selector.scores_


if __name__ == '__main__':
    logger = get_logger("debug")

    X_train, X_test, y_train, y_test = Get_normalize_data.get_all_data(c.model_folder)

    compare_quantitative_features(X_train, y_train)

