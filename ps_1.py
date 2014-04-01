#!/usr/bin/env python3

"""
Solution to the first problem set.

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
import binascii
from utils.functions import xor_strings

THRESHOLD_SINGULAR = 0.65
THRESHOLD_SPACE = 0.30


class EncryptedMsg(object):
    """
    Class modelling an encrypted message.

    Class modeling a titled encrypted message. Appropriate message
    type is checked at construction time. Defines a static method
    for loading messages from file.

    Attributes:
        title: the title of the message
        msg: the content of the message
    """

    def __init__(self, title, msg):
        """Inits the class with a title and some content."""
        if not isinstance(msg, bytes):
            msg = binascii.unhexlify(msg)

        self.title = title
        self.message = msg

    def __str__(self):
        """Returns the concatenated title and content."""
        return "%s:\n%s" % (self.title, self.message)

    @classmethod
    def load(cls, path):
        """Load a list of messages from the given path."""
        msg_list = []

        with open(path) as file:
            while True:
                title = file.readline().rstrip(":\n")
                msg = file.readline().rstrip()

                if not title or not msg:
                    break

                msg_list.append(cls(title, msg))
                file.readline()

        return msg_list


def main(path):
    """
    Main function of this script.

    The main function expects as argument the path to a file containing
    encrypted messages and assumes the last one should be decrypted.
    The messages are loaded and an approximation of the target message
    is given in linear time.

    Args:
        path: the path to the encrypted messages
    """
    messages = EncryptedMsg.load(path)
    target = messages.pop()

    positions = {}

    for message in messages:
        xor_msg = xor_strings(target.message, message.message)

        for i in range(len(xor_msg)):
            char = xor_msg[i]

            if (65 <= char <= 90) or (97 <= char <= 122):
                char_list = positions.get(i, [])
                char_list.append(chr(char).swapcase())
                positions[i] = char_list

    decrypted = []
    non_singular = []

    for position, values in positions.items():
        char_counter = {}

        for char in values:
            count = char_counter.get(char, 0)
            char_counter[char] = count + 1

        most_frequent = max(char_counter, key=char_counter.get)
        frequency = char_counter[most_frequent] / len(values)

        if frequency >= THRESHOLD_SINGULAR:
            decrypted.append(most_frequent)
        elif frequency <= THRESHOLD_SPACE:
            decrypted.append(" ")
        else:
            decrypted.append("#")
            non_singular.append((position, values))

    print("Decrypted message:")
    print("".join(decrypted))
    print("\nMissing values: (#)")

    for position, values in non_singular:
        print("\t%4d: %s" % (position, values))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        exit(1)

    main(sys.argv[1])
