import ConfigParser

def read_config(path_to_config):
    config = ConfigParser.ConfigParser(allow_no_value=True)
    config.read(path_to_config)
    path_to_dataset = config.get('PATHS', 'path_to_dataset')
    return [path_to_dataset]