import os
import config as c
import shutil
from logger import get_logger

logger = get_logger('debug')

if __name__ == '__main__':

    for folder in os.listdir(c.results_folder):
        for file in os.listdir(c.results_folder + folder + "/"):
            filename = c.results_folder + folder + "/" + file
            os.remove(filename)
            logger.info("File deleted : {}".format(filename))