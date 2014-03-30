__author__ = 'Luka Sterbic'

import binascii
from utils import xor_strings

THRESHOLD_SINGULAR = 0.65
THRESHOLD_SPACE = 0.30


class EncryptedMsg(object):
    """
    Class modelling an encrypted message

    Checks for appropriate message type at construction time.
    Defines static method for loading messages from file.
    """
    def __init__(self, title, message):
        if not isinstance(message, bytes):
            message = binascii.unhexlify(message)

        self.title = title
        self.message = message

    def __str__(self):
        return self.title + ":\n" + self.message

    @staticmethod
    def load(path):
        messages = []

        with open(path) as file:
            while True:
                title = file.readline().rstrip(':')
                message = file.readline().rstrip()

                if not title or not message:
                    break

                messages.append(EncryptedMsg(title, message))
                file.readline()

        return messages

if __name__ == "__main__":
    messages = EncryptedMsg.load("data/ps_1_messages.txt")
    target = messages.pop()

    positions = {}

    for message in messages:
        xor_msg = xor_strings(target.message, message.message)

        for i in range(len(xor_msg)):
            char = xor_msg[i]

            if (char >= 65 and char <= 90) or (char >= 97 and char <= 122):
                list = positions.get(i, [])
                list.append(chr(char).swapcase())
                positions[i] = list

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