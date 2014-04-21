#!/usr/bin/env python3

"""
Solution to the third Cryptography I problem set.

The script expects two arguments, the path to an input file and the
path to an output file. The selected input file is broken in 1 KB
chunks and for each chunk a hash is calculated. The underlying hash
function is SHA256. Hash h_i is the hash calculated for the i-th chunk
concatenated with the h_(i+1)-th hash. This script generates all the
necessary keys and saves them to the specified output path.
output path.

Dependencies:
    PyCrypto

Usage:
    python3 ps_3.py input_path output_path

Args:
    input_path: the path to the input file
    output_path the path to the output file
"""
__author__ = 'Luka Sterbic'

import sys
import binascii

from Crypto.Hash import SHA256


def main(input_path, output_path):
    """
    Main function of this script.

    The main functions reads the file at the given path, calculates
    and outputs to file the hashes h_i for each 1KB chunk.

    Args:
        input_path: the path to the input file
        output_path the path to the output file
    """
    chunks = []
    hashes = []

    with open(input_path, "rb") as file:
        while True:
            chunk = file.read(1024)

            if not chunk:
                break
            else:
                chunks.append(chunk)

    chunk_hash = SHA256.new(chunks.pop()).digest()
    hashes.append(chunk_hash)

    while chunks:
        sha = SHA256.new(chunks.pop())
        sha.update(chunk_hash)
        chunk_hash = sha.digest()
        hashes.append(chunk_hash)

    hashes = list(reversed(hashes))

    with open(output_path, "w") as file:
        for h_i in range(len(hashes)):
            chunk_hash = binascii.hexlify(hashes[h_i]).decode("ascii")
            print("h_%d: %s" % (h_i, chunk_hash), file=file)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        exit(1)

    main(sys.argv[1], sys.argv[2])
