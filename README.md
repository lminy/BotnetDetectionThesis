# BotnetDetectorThesis

This implementation was realized for my master thesis on "Botnet detection in encrypted traffic - a machine learning approach" 

## Configuration

## Run

Follow these steps:
1. run features_extraction/MainBro.py to extract the features in results/features.csv
2. run machine_learning/normalize_and_split.py to generate data to feed to ML
3. run train.py to generate models

## Choosing the set of features to train

Pass the setname of the features to use through 
```Python
Get_normalize_data.get_all_data("model_folder", "set_name")
```
setname can take the value "all", "dns", "https", "reduced", "reduced_30", "reduced_40" and "enhanced_30".
To create a new set of features, just complete the *features_set* dictionnary present in the *get_all_data(...)* function

## Generate the enhanced features set
The enhanced features set contains cipher suites from ClientHello packets.
Unfortunately the information is not available by default in Bro logs.
Therefore it is required to extract them by hand. The tls_finger.bro script from [securityartwork.es](https://www.securityartwork.es/2017/02/02/tls-client-fingerprinting-with-bro/) has been used in order to do this extraction
Moreover, to avoid re-computing the whole features set (which is time and ressources consuming),
the features are calculated separately then added to the csv with all features.

Here are the steps to generate the enhanced features set:

1. Install [Bro](https://www.bro.org/download/index.html) or install [SecurityOnion](https://securityonion.net/) and put the **tls_finger.bro** file into the folder **"/usr/local/share/bro/site"**
2. Use **extract_bro_ciphers.py** to extract cipher suites from Bro logs
3. Use **feature_extraction/compute_ciphersuites_features.ipynb** to compute the features from Bro logs and store them in **results/model/features_enhanced.csv**


## Project structure
- **dataset_tools/** -> contains all the tools related to the datasets (download, collect infected IPs, label and discard datasets)
    - **download_datasets.py**: to download the desired datasets
    - **discard_unuseful_datasets.py**: to discard datasets that have no flows labelled
    - **collect_infected_ips.py**: to collect infected and normal IPs from README.html files present in the dataset folders (uses a regex to parse the files)
    - **label_normal_datasets.py**: to label normal datasets
    - **label_mcfp_datasets.py**: to label MFCP datasets (excluding the "CTU-13 Dataset" which is already labelled)
- **features_extraction/** -> contains the scripts that extract the features. Credits go to [Frantisek Strasak](https://github.com/frenky-strasak) for HTTPS features extractions.
- **machine_learning/** -> contains the scripts to normalize the data from the features extracted and train the model
- **results/{graphs|logs|model}** -> default folders for generated graphs, models and logs
- **results_backup/** -> contains the backup results of the different experiments
- **statistics/** -> contains the scripts to analyze the features extracted and the models generated
- **tools/** -> Various tools: 
    - **tls_finger.bro**: Bro script to extract cipher suites
    - **extract_bro_ciphers.py**: Python script to extract logs + cipher suites from pcap's
    - **backup_results.py**: to backup the result folder (requires "results_folder_backup" to be set in config file)
    - **delete_results.py**: to delete the result folder
    - **split_alexa.py**: to sort and split alexa top websites in multiple files for quicker lookups

## Main requirements
- [Python 2.7](https://www.python.org/download/releases/2.7/)
- [Jupyter notebook](https://jupyter.org/install)
- [Numpy](http://www.numpy.org/)
- [SciPy](https://www.scipy.org/install.html)
- [sklearn](http://scikit-learn.org/stable/install.html)
- [XGBoost](https://github.com/dmlc/xgboost/tree/master/python-package)


## License
BotnetDetectorThesis is released under the MIT license. Credits go to František Střasák for some parts of the code (https://github.com/frenky-strasak/HTTPSDetector).