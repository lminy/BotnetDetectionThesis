import csv

def binarySearch(alist, item):
    first = 0
    last = len(alist)-1
    found = False

    while first<=last and not found:
        pos = 0
        midpoint = (first + last)//2
        if alist[midpoint] == item:
            pos = midpoint
            found = True
        else:
            if item < alist[midpoint]:
                last = midpoint-1
            else:
                first = midpoint+1
    return found

def sort_and_write(l, filename):
    l_sorted = sorted(l, key=str.lower)
    with open(filename, 'wb') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=' ', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(l_sorted)



with open('alexa.csv', 'rb') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',')
    alexa = list()
    for row in csvreader:
        alexa.append(row[1])

#sort_and_write(alexa[:100], 'top-100.csv')
#sort_and_write(alexa[100:1000], 'top-101-1000.csv')
#sort_and_write(alexa[1000:10000], 'top-1001-10000.csv')
#sort_and_write(alexa[10000:100000], 'top-10001-100000.csv')
#sort_and_write(alexa[100000:1000000], 'top-100001-1000000.csv')

alexa_sorted = sorted(alexa, key=str.lower)


import time
import datetime
"""
start_time = time.time()
binarySearch(alexa_sorted, "wikipedia.org")
total_time = datetime.timedelta(seconds=time.time() - start_time)
print("Binary search total time : " + str(total_time))#.strftime('%H:%M:%S'))

start_time = time.time()
"wikipedia.org" in alexa_sorted
total_time = datetime.timedelta(seconds=time.time() - start_time)
print("In search total time : " + str(total_time))#.strftime('%H:%M:%S'))
"""

print binarySearch(alexa_sorted, "wikiphjhedia.org")

