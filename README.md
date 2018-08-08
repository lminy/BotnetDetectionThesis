# BotnetDetectorThesis

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
To create a new set of features, just complete the *features_set* dictionnary present in the *get_all_data* function

## Generate the enhanced features set
The enhanced features set contains cipher suites from ClientHello packets.
Unfortunelaty the information is not available by default in Bro logs.
Therefore you it is required to extract them by hand. The tls_finger.bro script from [securityartwork.es](https://www.securityartwork.es/2017/02/02/tls-client-fingerprinting-with-bro/) has been used in order to do this extraction
Moreover, to avoid re-computing the whole features set (which is time and ressources consuming),
the features are calculated separetely then added to the csv with all features.

Here are the steps to generate the enhanced features set:

1. Install [Bro](https://www.bro.org/download/index.html) or install [SecurityOnion](https://securityonion.net/) and put the **tls_finger.bro** file into the folder **"/usr/local/share/bro/site"**
2. Use **extract_bro_ciphers.py** to extract cipher suites from Bro logs
3. Use **feature_extraction/compute_ciphersuites_features.ipynb** to compute the features from Bro logs and store them in **results/model/features_enhanced.csv**