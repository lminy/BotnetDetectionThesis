import config as c
import csv


def get_features_name():
    with open(c.model_folder + "features.csv", 'r') as csvfile:
        csvreader = csv.reader(csvfile, lineterminator='\n', delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        features_name = csvreader.next()[1:-1]
        return features_name

if __name__ == '__main__':

    features_name = get_features_name()

    latex_table = "\\begin{table}[!h]\n" \
                  "\centering\n" \
                  "\\begin{tabular}{llll}\n"
    latex_table += "\\textbf{{{}}} & \\textbf{{{}}} & \\textbf{{{}}} & \\textbf{{{}}} \\\\ \hline \n".format("", "ID", "Feature name", "proposed in")


    dns_features_name = features_name[41:]

    for i, feature in enumerate(dns_features_name):
        latex_table += "{} & F{} & {} & {} \\\\ \n".format("",i+1,feature.replace("_", " "),"")

    latex_table += "\end{tabular}\n" \
                   "\caption{DNS Features}\n" \
                   "\label{table:dns_features}\n" \
                   "\end{table}\n"



    print latex_table


