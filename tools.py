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