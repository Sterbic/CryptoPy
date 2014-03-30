"""
Solution to the first problem set

The script expects one argument, the path to a file with the encrypted
messages. The last message in the file is assumed to be the target
message for decryption. The script output a tentative decryption and
some possibilities for the missing values.
"""
__author__ = 'Luka Sterbic'

import sys
import binascii
from utils.functions import xor_strings

THRESHOLD_SINGULAR = 0.65
THRESHOLD_SPACE = 0.30


class EncryptedMsg(object):
    """
    Class modelling an encrypted message

    Checks for appropriate message type at construction time.
    Defines static method for loading messages from file.
    """
    def __init__(self, title, msg):
        if not isinstance(msg, bytes):
            msg = binascii.unhexlify(msg)

        self.title = title
        self.message = msg

    def __str__(self):
        return self.title + ":\n" + self.message

    @staticmethod
    def load(path):
        msg_list = []

        with open(path) as file:
            while True:
                title = file.readline().rstrip(':')
                msg = file.readline().rstrip()

                if not title or not msg:
                    break

                msg_list.append(EncryptedMsg(title, msg))
                file.readline()

        return msg_list

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ps1.py path_to_messages")
        exit(1)

    messages = EncryptedMsg.load(sys.argv[1])
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

    for item in positions.items():
        char_counter = {}

        for char in item[1]:
            count = char_counter.get(char, 0)
            char_counter[char] = count + 1

        most_frequent = max(char_counter, key=char_counter.get)
        frequency = char_counter[most_frequent] / len(item[1])

        if frequency >= THRESHOLD_SINGULAR:
            decrypted.append(most_frequent)
        elif frequency <= THRESHOLD_SPACE:
            decrypted.append(' ')
        else:
            decrypted.append('#')
            non_singular.append(item)

    print("Decrypted message:")
    print("".join(decrypted))
    print("\nMissing values: (#)")
    [print(item) for item in non_singular]