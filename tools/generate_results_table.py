import config as c
import csv
import string


def generate_table(results, headers, caption, label):
    latex_table = "\\begin{table}[!h]\n" \
                  "\centering\n" \
                  "\\begin{adjustbox}{max width=\\textwidth}\n" \
                  "\\begin{tabular}{lllllllllll}\n"

    latex_table += " & ".join(map(lambda h: "\\textbf{{{}}}".format(h), headers))
    latex_table += "\\\\ \hline \n"

    for line in results.split("\n"):
        line = map(string.strip, line.split("\t"))
        latex_table += line[0]
        for e in line[1:]:
            latex_table += " & " + str(round(float(e), 3))
        latex_table += ""
        latex_table += " \\\\ \n"

    latex_table += "\end{tabular}\n" \
                   "\end{adjustbox}\n"
    latex_table += "\caption{{{}}}\n".format(caption)
    latex_table += "\label{{{}}}\n".format(label)
    latex_table += "\end{table}\n"

    return latex_table


def generate_summary_table(results_https, results_https_dns, results_enhanced_30, headers, caption, label):
    models_order = ["XGBoost", "Random forest", "AdaBoost", "Log. Regression", "Neural net", "NB - Gaussian", "k-NN", "Decision tree"]

    https = dict()
    for line in results_https.split("\n"):
        line = map(string.strip, line.split("\t"))
        https[line[0]] = [round(float(l),3) for l in line[1:]]

    https_dns = dict()
    for line in results_https_dns.split("\n"):
        line = map(string.strip, line.split("\t"))
        https_dns[line[0]] = [round(float(l),3) for l in line[1:]]

    enhanced_30 = dict()
    for line in results_enhanced_30.split("\n"):
        line = map(string.strip, line.split("\t"))
        enhanced_30[line[0]] = [round(float(l),3) for l in line[1:]]

    latex_table = "\\begin{table}[htbp]\n"
    latex_table += "\\begin{center}\n" \
        "\\begin{tabular}{l|ll||ll||ll|} %l:left c:center r:right |:table lines\n" \
        "\cmidrule[1pt]{2-7} % 1pt is the thickness 3-10 is column number\n" \
        "&\multicolumn{2}{c||}{HTTPS}&\multicolumn{2}{c||}{HTTPS + DNS}&\multicolumn{2}{c|}{Enhanced} \\\\ \\cmidrule{2-7}\n" \
        "&\multicolumn{1}{c|}{Acc}&\multicolumn{1}{c||}{FPR}&\multicolumn{1}{c|}{Acc}&\multicolumn{1}{c||}{FPR}&\multicolumn{1}{c|}{Acc}&\multicolumn{1}{c|}{FPR}\\\\ \\midrule \n"

    for model in models_order:
        latex_table += "{} & {:.3f} & {:.3f} & {:.3f} & {:.3f} & {:.3f} & {:.3f} \\\\ \n".format(model, https[model][4], https[model][3], https_dns[model][4], https_dns[model][3], enhanced_30[model][4], enhanced_30[model][3])

    latex_table += "\\midrule\end{tabular}\n" \
                   "\end{center}"
    latex_table += "\caption{{{}}}\n".format(caption)
    latex_table += "\label{{{}}}\n".format(label)
    latex_table += "\end{table}\n"

    return latex_table

if __name__ == '__main__':

    headers = ['Model', 'Best score', 'TPR', 'TNR', 'FPR', 'Acc', 'Err', 'Pre', 'F-M', 'MCC', 'AUC']

    # https
    results_https = "XGBoost	0.9853618866901599	0.984	0.987	0.013	0.985	0.015	0.987	0.985	0.971	0.985\n \
        Random forest	0.97289238276	0.969	0.977	0.023	0.973	0.027	0.977	0.973	0.946	0.973\n \
        Decision tree	0.955543507726	0.95	0.961	0.039	0.956	0.044	0.961	0.955	0.911	0.956\n \
        AdaBoost	0.951206288967	0.952	0.95	0.05	0.951	0.049	0.95	0.951	0.902	0.951\n \
        k-NN	0.880726484142	0.871	0.89	0.11	0.881	0.119	0.888	0.88	0.762	0.881\n \
        Neural net	0.8359989156953104	0.862	0.81	0.19	0.836	0.164	0.819	0.84	0.673	0.836\n \
        Log. Regression	0.817565735972	0.796	0.839	0.161	0.818	0.182	0.832	0.813	0.636	0.818\n \
        NB - Gaussian	0.5917592843589049	0.234	0.949	0.051	0.592	0.408	0.821	0.364	0.262	0.591"

    # https + dns
    results_https_dns = "XGBoost	0.9886148007590133	0.985	0.992	0.008	0.989	0.011	0.992	0.989	0.977	0.989\n \
        AdaBoost\t0.970452697208	0.971	0.97	0.03	0.97	0.03	0.97	0.97	0.941	0.97\n \
        Random forest	0.969910544863	0.958	0.982	0.018	0.97	0.03	0.982	0.97	0.94	0.97\n \
        Decision tree	0.956627812415	0.946	0.967	0.033	0.957	0.043	0.967	0.956	0.913	0.957\n \
        k-NN	0.905394415831	0.893	0.918	0.082	0.905	0.095	0.916	0.904	0.811	0.905\n \
        Neural net	0.9024125779343996	0.939	0.866	0.134	0.902	0.098	0.875	0.906	0.807	0.902\n \
        Log. Regression\t0.877744646246	0.863	0.893	0.107	0.878	0.122	0.889	0.876	0.756	0.878\n \
        NB - Gaussian	0.750338845216	0.555	0.945	0.055	0.75	0.25	0.91	0.69	0.544	0.75\n"

    # enhanced_30 feature set
    results_enhanced_30 = "XGBoost	0.999	0.995	0.999	0.001	0.997	0.003	0.999	0.997	0.994	0.997\n \
        Random forest	0.999453850355	0.993	0.999	0.001	0.996	0.004	0.999	0.996	0.992	0.996\n \
        Decision tree	0.999437570304	0.964	0.999	0.001	0.982	0.018	0.999	0.981	0.964	0.982\n \
        k-NN	0.998904709748	0.99	0.999	0.001	0.994	0.006	0.999	0.994	0.989	0.994\n \
        AdaBoost	0.997018162104	0.995	0.999	0.001	0.997	0.003	0.999	0.997	0.994	0.997\n \
        Neural net	0.996476009759	0.993	0.999	0.001	0.996	0.004	0.999	0.996	0.993	0.996\n \
        Log. Regression	0.995662781242	0.992	0.999	0.001	0.996	0.004	0.999	0.996	0.991	0.996\n \
        NB - Gaussian	0.994578476552	0.993	0.996	0.004	0.995	0.005	0.996	0.995	0.989	0.995\n \
        "
    results_enhanced_30 = "XGBoost	0.9994547437295529	0.994574064026	0.999458288191	0.000541711809317	0.997018162104	0.00298183789645	0.99945474373	0.997008430786	0.994048130058	0.9970161761083636\n \
        Log. Regression	0.9994532531437944	0.991861096039	0.999458288191	0.000541711809317	0.995662781242	0.00433721875847	0.999453253144	0.995642701525	0.991354060016	0.9956596921148746\n \
        Decision tree	0.999437570304	0.964188822572	0.999458288191	0.000541711809317	0.981837896449	0.0181621035511	0.999437570304	0.981496824082	0.964273690987	0.981823555381\n \
        Random forest	0.998910675381	0.995116657623	0.998916576381	0.00108342361863	0.997018162104	0.00298183789645	0.998910675381	0.997010057081	0.994043460307	0.997016617002\n \
        k-NN	0.998904709748	0.989690721649	0.998916576381	0.00108342361863	0.99430740038	0.00569259962049	0.998904709748	0.994276369583	0.988656700454	0.994303649015\n \
        AdaBoost	0.997018162104	0.994574064026	0.999458288191	0.000541711809317	0.997018162104	0.00298183789645	0.99945474373	0.997008430786	0.994048130058	0.997016176108\n \
        Neural net	0.996476009759	0.993488876831	0.999458288191	0.000541711809317	0.996476009759	0.00352399024126	0.999454148472	0.996462585034	0.992969638722	0.996473582511\n \
        NB - Gaussian	0.994578476552	0.993488876831	0.995666305525	0.00433369447454	0.994578476552	0.00542152344809	0.995649809679	0.994568169473	0.989159252766	0.994577591178\n"


    #print(generate_table(results_https, headers, "Result HTTPS", "table:result_https"))

    #print(generate_table(results_https_dns, headers, "Result HTTPS + DNS", "table:result_https_dns"))

    #print(generate_table(results_enhanced_30, headers, "Result Enhanced features set", "table:result_enhanced_features_set"))

    print(generate_summary_table(results_https, results_https_dns, results_enhanced_30, headers, "Summary of the results", "table:result_summary"))

