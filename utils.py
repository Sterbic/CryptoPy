__author__ = 'Luka'

def xor_strings(a, b):
    if not isinstance(a, bytes):
        a = a.encode('ascii')

    if not isinstance(b, bytes):
        b = b.encode('ascii')

    length = min(len(a), len(b))
    string = []

    for i in range(length):
        string.append(a[i] ^ b[i])

    return bytes(string)