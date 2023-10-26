# Import required modules
import os
from conjur_iam_client import *
from conjur_iam_client import create_conjur_iam_client_from_env

# Set environment variables for Conjur authentication
appliance_url = os.environ['CONJUR_APPLIANCE_URL']
service_id = os.environ['AUTHN_IAM_SERVICE_ID']
username = os.environ['CONJUR_AUTHN_LOGIN']
conjur_account = os.environ['CONJUR_ACCOUNT']
if (os.environ['TARGET']=="cloud"):
    cert_file=None
else:
    cert_file = os.environ['CONJUR_CERT_FILE']

# Create Conjur IAM API key and assert it is not None
conjur_api_key = create_conjur_iam_api_key()
assert conjur_api_key is not None, "Conjur API key should not be None"
print(conjur_api_key)

# Get Conjur IAM session token and assert it is not None
conjur_session_token = get_conjur_iam_session_token(appliance_url, conjur_account, service_id, username, cert_file)
assert conjur_session_token is not None, "Conjur session token should not be None"
print(conjur_session_token)

# Create Conjur IAM client and assert it is not None
conjur_client = create_conjur_iam_client(appliance_url, conjur_account, service_id, username, cert_file)
assert conjur_client is not None, "Conjur IAM client should not be None"

# Test the list method of Conjur IAM client and assert it returns a list
conjur_list = conjur_client.list()
assert isinstance(conjur_list, list), "Conjur list should be a list"
print("this is list", conjur_list)

if (os.environ['TARGET']=="cloud"):
    variable_value = conjur_client.get('data/database/username')
    print(f"variable_value on Conjur cloud: {variable_value}")
else:
    variable_value = conjur_client.get('myspace/database/username')
    print(f"variable_value on Conjur : {variable_value}")
