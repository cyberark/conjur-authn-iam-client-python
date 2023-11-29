import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
from iam_provider import write_and_flush
import sys

class TestIAMProvider(unittest.TestCase):

    @patch('sys.stdout', new_callable=StringIO)
    @patch('conjur_iam_client.create_conjur_iam_client_from_env')
    def test_variable_retrieval_successful(self, mock_create_client, mock_stdout):
        mock_create_client.return_value.get.return_value = b'Some value'
        variable_id = 'some_variable_id'
        write_and_flush(sys.stdout, variable_id)
        self.assertEqual(mock_stdout.getvalue(), 'some_variable_id')


if __name__ == '__main__':
    unittest.main()
