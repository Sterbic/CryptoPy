#!/usr/bin/env python3

"""
Solution to the second Cryptography I problem set.

The script expects one argument, the path to a file with the encrypted
messages. The messages should provide the key which was used for the
encryption process and the AES mode used.

Dependencies:
    PyCrypto

Usage:
    python3 ps_2.py path

Args:
    path: the path to the encrypted messages
"""
__author__ = 'Luka Sterbic'

import sys

from Crypto.Cipher import AES

from utils.functions import xor_strings
from utils.structs import EncryptedMsg, AESKey


def load_keys_and_msgs(path):
    """
    Loads a (key, message) list from a file.

    Opens the given path an loads a list of AES encrypted messages
    with the associated secret keys.

    Args:
        path: the path to the file containing keys and messages
    """
    keys_msgs = []

    with open(path) as file:
        while True:
            line = file.readline().rstrip()

            if not line:
                break

            key = AESKey(line[:3], line.split(": ")[1])

            title = file.readline().rstrip(":\n")
            msg = []

            while True:
                line = file.readline().rstrip()

                if line:
                    msg.append(line)
                else:
                    break

            if not title or not msg:
                break

            keys_msgs.append((key, EncryptedMsg(title, "".join(msg))))

    return keys_msgs


def cbc_decode(key, message):
    """
    Decrypt message in CBC mode.

    This function decrypts the give message using the CBC AES mode and
    the given key. The 16 byte IV should be prepended to the message
    content and the PKCS5 padding scheme is assumed. The result is
    returned as a python string.

    Args:
        key: the 128 bit AES key
        message: CBC mode AES encrypted message

    Returns:
        decrypted message content
    """
    init_vector = message.message[:16]
    msg = message.message[16:]

    cipher = AES.new(key.key, mode=AES.MODE_ECB)
    decrypted = []

    i = 0
    while i < len(msg):
        block = msg[i:i + 16]
        i += 16

        aes_output = cipher.decrypt(block)

        decrypted_block = xor_strings(aes_output, init_vector)
        if i >= len(msg):
            if decrypted_block[-1] == 16:
                break
            else:
                decrypted_block = decrypted_block[:-decrypted_block[-1]]

        decrypted.append(decrypted_block)
        init_vector = block

    return "".join([part.decode("utf-8") for part in decrypted])


def ctr_decode(key, message):
    """
    Decrypt message in CTR mode.

    This function decrypts the give message using the CTR AES mode and
    the given key. The 16 byte IV should be prepended to the message
    content. The result is returned as a python string.

    Args:
        key: the 128-bit AES key
        message: CTR mode AES encrypted message

    Returns:
        decrypted message content
    """
    init_vector = message.message[:16]
    msg = message.message[16:]

    cipher = AES.new(key.key, mode=AES.MODE_ECB)
    decrypted = []

    i = 0
    while i < len(msg):
        block = msg[i:i + 16]
        i += 16

        aes_output = cipher.encrypt(init_vector)

        decrypted.append(xor_strings(aes_output, block))

        init_vector = list(init_vector)
        for j in reversed(range(len(init_vector))):
            init_vector[j] += 1

            if init_vector[j] == 256:
                init_vector[j] = 0
            else:
                break

        init_vector = bytes(init_vector)

    return "".join([part.decode("utf-8") for part in decrypted])


def main(path):
    """
    Main function of this script.

    The main function expects as argument the path to a file containing
    AES encrypted messages paired keys. A message can either be
    encrypted using the CBC mode or the CTR mode. For every entry the
    decrypted content is computed and printed on stdout.

    Args:
        path: the path to the file containing keys and messages
    """
    for key, message in load_keys_and_msgs(path):
        if key.mode == AESKey.MODE_CBC:
            content = cbc_decode(key, message)
        elif key.mode == AESKey.MODE_CTR:
            content = ctr_decode(key, message)
        else:
            raise ValueError("Unknown AES mode")

        print(message.title)
        print(content + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        exit(1)

    main(sys.argv[1])
