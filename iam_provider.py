#!/usr/bin/python3
"""Creates a Conjur IAM client using environment variables."""

import sys

from conjur_iam_client import create_conjur_iam_client_from_env


def write_and_flush(pipe, message):
    """
    Writes the given message to the pipe and immediately flushes the output buffer.
    """
    pipe.write(message)
    pipe.flush()

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        write_and_flush(sys.stderr, 'No variable ID was provided.')
        sys.exit(1)

    VARIABLE_ID = sys.argv[1]
    conjur_client = create_conjur_iam_client_from_env()
    value = conjur_client.get(VARIABLE_ID)
    if value in (None, ""):
        write_and_flush(sys.stderr, f"{VARIABLE_ID} could not be retrieved")
        sys.exit(1)
    write_and_flush(sys.stdout, value.decode('utf-8'))
