import logging
import config as c

logger = None

def get_logger(loglevel):
    global logger
    if logger is not None:
        return logger

    numeric_level = getattr(logging, loglevel.upper(), logging.INFO)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    import sys
    import os
    module_name = str(os.path.basename(sys.modules['__main__'].__file__)).split('.')[0]

    logger = logging.getLogger(module_name)
    logger.setLevel(numeric_level)
    # create file handler which logs even debug messages
    fh = logging.FileHandler(c.logs_folder + module_name + '.log')
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t\t%(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.info("Logger created!")
    return logger