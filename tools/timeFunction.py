

def benchmark(func, *params):
    import datetime
    import time
    start_time = time.time()
    return_value = func(*params) if params else func()
    total_time = datetime.timedelta(seconds=time.time() - start_time)
    print("Function " + func.__name__ + " - execution time : " + str(total_time))#.strftime('%H:%M:%S'))
    return return_value


def test():
    total = 0
    for i in range(0, 10000):
        total +=i
    return total

def sum(param1, param2):
    return param1 + param2

print benchmark(sum, 1, 2)

print benchmark(test)