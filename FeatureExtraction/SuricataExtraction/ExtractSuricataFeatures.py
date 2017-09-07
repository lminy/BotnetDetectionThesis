import json
from Connection4tupleSuricata import Connection4tupleSuricata


class ExtractSuricataFeatures:

    def __init__(self):
        self.connection_4_tuple = dict()

    def create_4_tuples(self, path):

        index = 0
        lines = 0
        with open(path + 'eve.json') as data_file:
            for line in data_file:
                data = json.loads(line)

                lines += 1

                # is TLS ?
                try:
                    if data["tls"]:
                        # print index, data["tls"]["subject"]
                        index += 1
                except:
                    continue



                # Find conn_4_tuple index.
                try:
                    conn_4_tuple_index = data["src_ip"], data["dest_ip"], data["dest_port"], data["proto"]
                except:
                    print "Error: conn index is not possible to create."
                    print line
                    break

                try:
                    self.connection_4_tuple[conn_4_tuple_index].add_ssl_flow()
                except:
                    self.connection_4_tuple[conn_4_tuple_index] = Connection4tupleSuricata(conn_4_tuple_index)

        data_file.close()
        print "all lines:", lines
        print "ssl lines:", index



if __name__ == '__main__':
    path = '/media/frenky/Fery/Frenky/Skola/StratosphereHTTPSDetector/Dataset/suricata/CTU-Malware-Capture-Botnet-261-1/suricata/'

    extractSuricataFeatures = ExtractSuricataFeatures()
    extractSuricataFeatures.create_4_tuples(path)
