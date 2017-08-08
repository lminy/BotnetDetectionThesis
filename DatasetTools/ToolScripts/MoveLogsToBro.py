"""
Move logs in sub folders to bro folders in sub folders.
"""

import shutil
import os

def move_to_bro(folder_path):
    if not os.path.exists(folder_path + "bro"):
        os.makedirs(folder_path + "bro")
    # all logs put to bro folder.
    for file in os.listdir(folder_path):
        if file.endswith('.log'):
            os.rename(folder_path + file, folder_path + "bro/" + file)
            # shutil.move(folder_path + file, folder_path + "bro/" + file)




def main():
    dataset_path = "/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/Dataset2/unpack_logs/"

    for dir in os.listdir(dataset_path):
        print dataset_path + dir + '/'
        move_to_bro(dataset_path + dir + '/')


if __name__ == '__main__':
    main()