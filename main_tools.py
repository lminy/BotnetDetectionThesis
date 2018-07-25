from logger import get_logger
logger = get_logger("debug")


def benchmark(func, *params):
    import datetime
    import time
    start_time = time.time()
    return_value = func(*params) if params else func()
    total_time = datetime.timedelta(seconds=time.time() - start_time)
    logger.debug("Function {} - execution time : {}".format(func.__name__, total_time))
    return return_value


# mean(), _ss and stddev comes from https://stackoverflow.com/a/27758326
def mean(data):
    """Return the sample arithmetic mean of data."""
    n = len(data)
    if n < 1:
        raise ValueError('mean requires at least one data point')
    return sum(data)/float(n) # in Python 2 use sum(data)/float(n)


def _ss(data):
    """Return sum of square deviations of sequence data."""
    c = mean(data)
    ss = sum((x-c)**2 for x in data)
    return ss


def stddev(data, ddof=0):
    """Calculates the population standard deviation
    by default; specify ddof=1 to compute the sample
    standard deviation."""
    n = len(data)
    if n < 2:
        raise ValueError('variance requires at least two data points')
    ss = _ss(data)
    pvar = ss/(n-ddof)
    return pvar**0.5