__author__ = 'Luka Sterbic'

import binascii


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