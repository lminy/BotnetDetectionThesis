
path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/2017_08_25/y_test.txt"

normal = 0
malware = 0
with open(path) as f:
    for line in f:
        if int(line) == 0:
            normal += 1
        elif int(line) == 1:
            malware += 1
        else:
            print "Error: More label !!!"
f.close()

print "----------------------"
print path
print "Malware:", malware
print "Normal:", normal