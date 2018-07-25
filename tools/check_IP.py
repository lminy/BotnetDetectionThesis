
def is_ipv4(str):
    l = str.split('.')
    if len(l) != 4:
        return False
    try:
        ip = map(int, l)
    except ValueError:
        return False
    if len(filter(lambda x: 0 <= x <= 255, ip)) == 4:
        return True
    return False

# True
print is_ipv4("192.168.1.1")
print is_ipv4("0.0.0.0")
print is_ipv4("255.255.255.255")

# False
print is_ipv4("255.255.255")
print is_ipv4("255.255.255.255.3")
print is_ipv4("255.255.255.erzr")

