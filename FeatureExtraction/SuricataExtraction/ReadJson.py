import json
from pprint import pprint


def create_4_tuples(path):
    with open(path + 'eve.json') as data_file:
        for line in data_file:
            data = json.loads(line)

            # Find conn_4_tuple index.
            conn_4_tuple_index = data["src_ip"], data["dest_ip"], data["dest_port"], data["proto"]
            print conn_4_tuple_index



            break


if __name__ == '__main__':
    path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/suricata/CTU-Malware-Capture-Botnet-261-1/suricata/'
    create_4_tuples(path)
