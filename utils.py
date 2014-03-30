__author__ = 'Luka Sterbic'


def xor_strings(a, b):
    """
    XOR two strings

    Takes two strings as input and returns a bytes object representing
    the XOR operation between them. If the given strings are not bytes
    they are converted to ascii encoded strings.
    """
    if not isinstance(a, bytes):
        a = a.encode('ascii')

    if not isinstance(b, bytes):
        b = b.encode('ascii')

    length = min(len(a), len(b))
    string = []

    for i in range(length):
        string.append(a[i] ^ b[i])

    return bytes(string)