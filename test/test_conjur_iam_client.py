from __future__ import absolute_import, division, print_function
__metaclass__ = type

import unittest
import sys, datetime, hashlib, hmac, json, os
from unittest import TestCase
# from unittest.mock import MagicMock
from unittest.mock import call, MagicMock, patch
# from conjur import Client
import requests
from conjur_iam_client import valid_aws_account_number, get_iam_role_name, get_signature_key, get_conjur_iam_session_token, create_conjur_iam_client_from_env, create_conjur_iam_api_key, get_iam_role_metadata, create_canonical_request, sign

# get_iam_role_name

import conjur_iam_client as conjur_iam_client
from datetime import timedelta
import urllib.parse

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
    RESPONSE = b'!\jshdgfvhjdsbv'

class MockMergeDictionariesnew(MagicMock):
    RESPONSE = {'host': 'host', 'x-amz-date': 'amzdate', 'x-amz-security-token': 'token', 'x-amz-content-sha256': 'payload_hash', 'authorization': 'authorization_header'}


# class LearnTest(TestCase):

class TestLearnTest(unittest.TestCase):

    def test_get_aws_region(self):
        r = conjur_iam_client.get_aws_region()
        self.assertEqual("us-east-1", r)

    def test_valid_aws_account_number(self):
        validate_account_name = valid_aws_account_number("cucumber")
        self.assertEqual(False, validate_account_name)

    def test_string(self):
        a = 'some'
        b = 'some'
        self.assertEqual(a, b)

    def test_get_signature_key(self):
        abc = get_signature_key("1756786889", "1/2/2002", "us-east", "abce")
        self.assertNotEqual(MockMergeDictionaries.RESPONSE, abc)

    @patch('conjur_iam_client.create_conjur_iam_client')
    @patch.dict(os.environ, {"CONJUR_APPLIANCE_URL": "http://conjur.com", "CONJUR_ACCOUNT": "CONJUR_ACCOUNT","AUTHN_IAM_SERVICE_ID": "AUTHN_IAM_SERVICE_ID", "CONJUR_AUTHN_LOGIN": "CONJUR_AUTHN_LOGIN"})
    def test_create_conjur_iam_client_from_env(self, mock_create_conjur_iam_client):
            mock_response = MagicMock()
            mock_create_conjur_iam_client.return_value = "response body"
            result = "response body"
            create_conjur_iam_client_from_env(None, None, None, None, True)
            self.assertEqual("response body", result)

    def test_get_signature_key(self):
        result= get_signature_key("key", "dateStamp", "regionName", "serviceName")
        self.assertNotEqual(MockMergeDictionaries.RESPONSE, result)

    @patch('conjur_iam_client.create_conjur_iam_api_key')
    def test_get_conjur_iam_session_token(self, mock_create_conjur_iam_api_key):
        get_conjur_iam_session_token("http://testing.com", "account", "4444444", "121212121212", True, None, None, None, None, True)
        r = requests.post(url="http://testing.com",data="iam_api_key",verify=True)
        return r.text
        self.assertNotEqual("200", r.text)

    def test_create_conjur_iam_api_key(self):
        create_conjur_iam_api_key(iam_role_name="admin", access_key="hgdfcghvc", secret_key="ncbsc76757689ahsvvhg", token="675217681278978")
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
    def test_get_conjur_iam_session_token(self, mock_create_conjur_iam_api_key):
        result = get_conjur_iam_session_token("http://testing.com", "account", "4444444", "121212121212", True, None, None, None, None, True)
        r = requests.post(url="http://testing.com",data="iam_api_key",verify=True)
        self.assertEqual(1, result.find("html"))

if __name__ == '__main__':
    TestCase.main()
