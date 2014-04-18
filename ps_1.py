#!/usr/bin/env python3

"""
Solution to the first Cryptography I problem set.

The script expects one argument, the path to a file with the encrypted
messages. The last message in the file is assumed to be the target
message for decryption. The script output a tentative decryption and
some possibilities for the missing values.

Usage:
    python3 ps_1.py path

Args:
    path: the path to the encrypted messages
"""
__author__ = "Luka Sterbic"

import sys

from utils.functions import xor_strings, extract_most_frequent
from utils.messages import EncryptedMsg

THRESHOLD_SINGULAR = 0.65


def retrieve_otp_key(messages, length):
    """
    Retrieve the key from a set of otp encoded messages.

    Given a set of messages encoded with the one time pad algorithm
    and the expected length of the used key try to retrieve the key
    using ascii xor properties.

    Args:
        messages: a set of otp encoded messages
        length: the expected length of the key

    Returns:
        the key used to encode the given messages
    """
    key = {}

    for target in messages:
        positions = {}

        for other in messages:
            if target is other:
                continue

            xor_msg = xor_strings(target.message, other.message)

            for i in range(length):
                char = xor_msg[i]

                if (65 <= char <= 90) or (97 <= char <= 122):
                    char_list = positions.get(i, [])
                    char_list.append(chr(char).swapcase())
                    positions[i] = char_list

        for position, values in positions.items():
            most_frequent, frequency = extract_most_frequent(values)

            if frequency >= THRESHOLD_SINGULAR:
                key_char = target.message[position] ^ ord(most_frequent)
                key_char_list = key.get(position, [])
                key_char_list.append(key_char)
                key[position] = key_char_list

    delete = []

    for position, values in key.items():
        most_frequent, frequency = extract_most_frequent(values)

        if frequency >= THRESHOLD_SINGULAR:
            key[position] = most_frequent
        else:
            delete.append(position)

    for position in delete:
        del key[position]

    return key


def main(path):
    """
    Main function of this script.

    The main function expects as argument the path to a file containing
    encrypted messages and assumes the last one should be decrypted.
    The messages are loaded and an approximation of the opt key is
    computed by pairwise xor-ing the given messages.

    Args:
        path: the path to the encrypted messages
    """
    messages = EncryptedMsg.load(path)
    target = messages[-1]

    key = retrieve_otp_key(messages, len(target.message))

    decrypted = []
    missing = []

    for i in range(len(target.message)):
        if i in key:
            char = target.message[i] ^ key[i]
            decrypted.append(chr(char))
        else:
            decrypted.append("#")
            missing.append(str(i))

    print("Decrypted message:")
    print("".join(decrypted))

    if missing:
        print("\nMissing key at indexes: %s" % ", ".join(missing))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        exit(1)

    main(sys.argv[1])
