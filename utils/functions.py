"""Utility functions for cryptography."""
__author__ = "Luka Sterbic"


def xor_strings(first, second):
    """
    XOR two strings.

    Takes two strings as input and returns a bytes object representing
    the XOR operation between them. If the given strings are not bytes
    they are converted to ascii encoded strings. The resulting string
    is of the same length as the shorter string between a and b.

    Args:
        first: the first string
        second: the second string

    Returns:
        bytes object representing XOR(a, b)
    """
    if not isinstance(first, bytes):
        first = first.encode("ascii")

    if not isinstance(second, bytes):
        second = second.encode("ascii")

    length = min(len(first), len(second))
    string = []

    for i in range(length):
        string.append(first[i] ^ second[i])

    return bytes(string)


def extract_most_frequent(char_list):
    """
    Find the most frequent character in a list.

    Given a list of characters find the most frequent one and its
    frequency of appearance.

    Args:
        char_list: a list of characters

    Returns:
        the most frequent character and its frequency
    """
    char_counter = {}

    for char in char_list:
        count = char_counter.get(char, 0)
        char_counter[char] = count + 1

    most_frequent = max(char_counter, key=char_counter.get)
    frequency = char_counter[most_frequent] / len(char_list)

    return most_frequent, frequency
