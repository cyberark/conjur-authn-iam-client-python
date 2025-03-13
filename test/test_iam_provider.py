"""Test cases for the IAM Provider functionality."""

import sys
import unittest
from io import StringIO
from unittest.mock import patch

from iam_provider import write_and_flush


class TestIAMProvider(unittest.TestCase):
    """Unit tests for the IAM Provider functionality."""
    @patch('sys.stdout', new_callable=StringIO)
    @patch('conjur_iam_client.create_conjur_iam_client_from_env')
    def test_variable_retrieval_successful(self, mock_create_client, mock_stdout):
        """Test case to verify successful retrieval of a secret from Conjur."""
        mock_create_client.return_value.get.return_value = b'Some value'
        variable_id = 'some_variable_id'
        write_and_flush(sys.stdout, variable_id)
        self.assertEqual(mock_stdout.getvalue(), 'some_variable_id')


if __name__ == '__main__':
    unittest.main()
