#!/usr/bin/python3
from conjur import Client
from conjur_iam_client import create_conjur_iam_client_from_env
import sys


def write_and_flush(pipe, message):
    pipe.write(message)
    pipe.flush()

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        write_and_flush(sys.stderr, 'No variable ID was provided.')
        sys.exit(1)

    variable_id = sys.argv[1]
    conjur_client = create_conjur_iam_client_from_env()
    value = conjur_client.get(variable_id)
    if value == None or value == "":
        write_and_flush(sys.stderr, '{} could not be retrieved'.format(variable_id))
        sys.exit(1)
    write_and_flush(sys.stdout, value.decode('utf-8'))

