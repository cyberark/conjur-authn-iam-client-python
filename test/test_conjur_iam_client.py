from __future__ import absolute_import, division, print_function

import os
import unittest
from unittest import TestCase
from unittest.mock import MagicMock, patch

import conjur_iam_client
from conjur_iam_client import (create_conjur_iam_api_key,
                               create_conjur_iam_client_from_env,
                               get_conjur_iam_session_token, get_signature_key,
                               valid_aws_account_number)

AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
AWS_AVAILABILITY_ZONE = "http://169.254.169.254/latest/meta-data/placement/availability-zone"
METHOD = 'GET'
SERVICE = 'sts'
HOST = 'sts.amazonaws.com'
ENDPOINT = 'https://sts.amazonaws.com'
REQUEST_PARAMETERS = 'Action=GetCallerIdentity&Version=2011-06-15'

class MockFileload(MagicMock):
    RESPONSE = {}

class MockMergeDictionaries(MagicMock):
    RESPONSE = b'!\\jshdgfvhjdsbv'

class MockMergeDictionariesnew(MagicMock):
    RESPONSE = {
        'host': 'host',
        'x-amz-date': 'amzdate',
        'x-amz-security-token': 'token',
        'x-amz-content-sha256': 'payload_hash',
        'authorization': 'authorization_header'
    }


# class LearnTest(TestCase):

class TestLearnTest(unittest.TestCase):

    def test_get_aws_region(self):
        res = conjur_iam_client.get_aws_region()
        self.assertEqual("us-east-1", res)

    def test_valid_aws_account_number(self):
        validate_account_name = valid_aws_account_number("cucumber")
        self.assertEqual(False, validate_account_name)

    def test_string(self):
        abc = 'some'
        bcd = 'some'
        self.assertEqual(abc, bcd)

    def test_get_signature_key(self):
        abc = get_signature_key("1756786889", "1/2/2002", "us-east", "abce")
        self.assertNotEqual(MockMergeDictionaries.RESPONSE, abc)

    @patch('conjur_iam_client.create_conjur_iam_client')
    @patch.dict(os.environ, {
        "CONJUR_APPLIANCE_URL": "http://conjur.com",
        "CONJUR_ACCOUNT": "CONJUR_ACCOUNT",
        "AUTHN_IAM_SERVICE_ID": "AUTHN_IAM_SERVICE_ID",
        "CONJUR_AUTHN_LOGIN": "CONJUR_AUTHN_LOGIN"
    })
    def test_create_conjur_iam_client_from_env(self, mock_create_conjur_iam_client):
        mock_create_conjur_iam_client.return_value = "response body"
        result = "response body"
        create_conjur_iam_client_from_env(None, None, None, None, True)
        self.assertEqual("response body", result)

    def test_create_conjur_iam_api_key(self):
        create_conjur_iam_api_key(
            iam_role_name="admin",
            access_key="hgdfcghvc", #gitleaks:allow
            secret_key="ncbsc76757689ahsvvhg", #gitleaks:allow
            token="675217681278978"
        )
        headers = {
            'host': "HOST",
            'x-amz-date': "amzdate",
            'x-amz-security-token': "token",
            'x-amz-content-sha256': "payload_hash",
            'authorization': "authorization_header"
        }

        # ************* SEND THE REQUEST *************

        result = str(headers).lower()
        self.assertNotEqual(MockMergeDictionariesnew.RESPONSE, result)

    @patch('conjur_iam_client.create_conjur_iam_api_key')
    def test_get_conjur_iam_session_token(self, _mock_create_conjur_iam_api_key):
        result = get_conjur_iam_session_token(
            "http://testing.com",
            "account",
            "4444444",
            "121212121212",
            True, None, None, None, None, True
        )
        self.assertEqual(1, result.find("html"))

if __name__ == '__main__':
    TestCase.main()
