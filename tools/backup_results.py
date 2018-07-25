import shutil
import os
import config as c
import time
from logger import get_logger

logger = get_logger('debug')


def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)


if __name__ == '__main__':
    src = c.results_folder
    dst = c.results_folder_backup + "result_" + time.strftime("%Y-%m-%d_%H-%M-%S")

    copytree(src, dst)
    logger.info("Results backuped to {}".format(dst))


