"""Utility classes for cryptography."""
__author__ = 'Luka Sterbic'

import binascii


class AESKey(object):
    """
    Class representing a key for the AES algorithm.

    Class representing a 128 bit key for the AES algorithm. The key is
    stored as bytes object while the mode should be either CBC or CTR.

    Attributes:
        mode: the AES mode the key is intended for
        key: bytes representation of the key
    """
    MODE_CBC = "CBC"
    MODE_CTR = "CTR"
    MODES = {MODE_CBC, MODE_CTR}

    def __init__(self, mode, key):
        """Inits the class with a mode and binary key."""
        if mode not in AESKey.MODES:
            raise ValueError("Unknown AES mode")

        self.mode = mode

        if not isinstance(key, bytes):
            key = binascii.unhexlify(key)

        if len(key) != 16:
            raise ValueError("Illegal key length")

        self.key = key


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
                msg = []

                while True:
                    line = file.readline().rstrip()

                    if line:
                        msg.append(line)
                    else:
                        break

                if not title or not msg:
                    break

                msg_list.append(cls(title, "".join(msg)))

        return msg_list
