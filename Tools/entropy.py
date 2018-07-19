import numpy as np
import math


"""
def entropy(vals):
    sum = 0.0
    norm = 0.0
    for v in vals:
        norm += v
        vals = [v/norm for v in vals]
    for v in vals:
        sum += (v*np.log(v))
        return -1.0 * sum


def entropy(X):
    probs = [np.mean(X == c) for c in set(X)]
    return np.sum(-p * np.log2(p) for p in probs)
"""


def entropy(string):
    "Calculates the Shannon entropy of a string"

    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]

    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy

print entropy("huhjkhuihjilhnuohy.www.google.com")