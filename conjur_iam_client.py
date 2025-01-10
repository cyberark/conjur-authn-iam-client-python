import sys, datetime, hashlib, hmac, json, os
import requests # pip install requests
from datetime import timedelta
import urllib.parse
from conjur_api import Client
from conjur_api.models import ConjurConnectionInfo, CredentialsData, SslVerificationMode
from conjur_api.providers import AuthnAuthenticationStrategy, SimpleCredentialsProvider
from importlib.metadata import version

# ************* REQUEST VALUES *************
AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
AWS_AVAILABILITY_ZONE = "http://169.254.169.254/latest/meta-data/placement/availability-zone"
METHOD = 'GET'
SERVICE = 'sts'
HOST = 'sts.amazonaws.com'
ENDPOINT = 'https://sts.amazonaws.com'
REQUEST_PARAMETERS = 'Action=GetCallerIdentity&Version=2011-06-15'

class ConjurIAMAuthnException(Exception):
    def __init__(self):
        Exception.__init__(self,"Conjur IAM authentication failed with 401 - Unauthorized. Check conjur logs for more information")

class IAMRoleNotAvailableException(Exception):
    def __init__(self):
        Exception.__init__(self,"Most likely the ec2 instance is configured with no or an incorrect iam role")

class InvalidAwsAccountIdException(Exception):
    def __init__(self):
        Exception.__init__(self,"The AWS Account ID specified in the CONJUR_AUTHN_LOGIN is invalid and must be a 12 digit number")

def valid_aws_account_number(host_id):
    parts = host_id.split("/")
    account_id = parts[len(parts)-2]
    if len(account_id) == 12:
        return True
    return False

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing

def get_aws_region():
    # return requests.get(AWS_AVAILABILITY_ZONE).text[:-1]
    return "us-east-1"

def get_iam_role_name():
    token = get_metadata_token()
    headers = {}
    if token:
        headers = {'X-aws-ec2-metadata-token': token}
    res = requests.get(AWS_METADATA_URL, headers=headers)
    return res.text

def get_metadata_token():
    """Request a session token for IMDSv2"""
    url = 'http://169.254.169.254/latest/api/token'
    headers = {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}  # TTL for the token
    try:
        response = requests.put(url, headers=headers, timeout=2)
        if response.status_code == 200:
            return response.text
        else:
            return None
    except requests.exceptions.RequestException:
        return None

def get_iam_role_metadata(role_name, token=None):
    headers = {}
    if token:
        headers = {'X-aws-ec2-metadata-token': token} 

    try:
        res = requests.get(AWS_METADATA_URL + role_name, headers=headers)
        if res.status_code == 404:
            raise IAMRoleNotAvailableException()
        elif res.status_code != 200:
            raise Exception(f"Error retrieving IAM role metadata: {r.status_code}")

        json_dict = json.loads(res.text)

        access_key_id = json_dict["AccessKeyId"]
        secret_access_key = json_dict["SecretAccessKey"]
        token = json_dict["Token"]

        return access_key_id, secret_access_key, token
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to get IAM role metadata: {str(e)}")

def create_canonical_request(amzdate, token, signed_headers, payload_hash):
    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Step 2: Create canonical URI--the part of the URI from domain to query
    # string (use '/' if no path)
    canonical_uri = '/'

    # Step 3: Create the canonical query string. In this example (a GET request),
    # request parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    # For this example, the query string is pre-formatted in the request_parameters variable.
    canonical_querystring = REQUEST_PARAMETERS

    # Step 4: Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ("").
    # payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()

    # Step 5: Create the canonical headers and signed headers. Header names
    # must be trimmed and lowercase, and sorted in code point order from
    # low to high. Note that there is a trailing \n.
    canonical_headers = 'host:' + HOST + '\n' + 'x-amz-content-sha256:' + payload_hash + '\n' + 'x-amz-date:' + amzdate + '\n' + 'x-amz-security-token:' + token + '\n'

    # Step 6: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers lists those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    # signed_headers = 'host;x-amz-content-sha256;x-amz-date;x-amz-security-token'

    # Step 7: Combine elements to create canonical request
    canonical_request = METHOD + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    return canonical_request

def create_conjur_iam_api_key(iam_role_name=None, access_key=None, secret_key=None, token=None):
    if iam_role_name is None:
        iam_role_name = get_iam_role_name()

    metadata_token = get_metadata_token()

    if access_key is None and secret_key is None and token is None:
        access_key, secret_key, token = get_iam_role_metadata(iam_role_name, metadata_token)

    region = get_aws_region()

    if access_key is None or secret_key is None:
        print('No access key is available.')
        sys.exit()

    # Create a date for headers and the credential string
    t = datetime.datetime.now(datetime.timezone.utc)
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    signed_headers = 'host;x-amz-content-sha256;x-amz-date;x-amz-security-token'
    payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
    canonical_request = create_canonical_request(amzdate, token, signed_headers, payload_hash)

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + SERVICE + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = get_signature_key(secret_key, datestamp, region, SERVICE)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # The signing information can be either in a query string value or in
    # a header named Authorization. This code shows how to use a header.
    # Create authorization header and add to request headers
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    # The request can include any headers, but MUST include "host", "x-amz-date",
    # and (for this scenario) "Authorization". "host" and "x-amz-date" must
    # be included in the canonical_headers and signed_headers, as noted
    # earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python 'requests' library.

    headers = {
        'host': HOST,
        'x-amz-date': amzdate,
        'x-amz-security-token': token,
        'x-amz-content-sha256': payload_hash,
        'authorization': authorization_header
    }

    # ************* SEND THE REQUEST *************
    return '{}'.format(headers).replace("'", '"')

def get_conjur_iam_session_token(appliance_url, account, service_id, host_id, cert_file, iam_role_name=None, access_key=None, secret_key=None, token=None, ssl_verify=True):
    if not valid_aws_account_number(host_id):
        raise InvalidAwsAccountIdException()

    appliance_url = appliance_url.rstrip("/")
    url = "{}/authn-iam/{}/{}/{}/authenticate".format(appliance_url, service_id, account, urllib.parse.quote(host_id, safe=''))
    iam_api_key = create_conjur_iam_api_key(iam_role_name, access_key, secret_key, token)

    # If cert file is not provided then assume conjur is using valid certificate
    if cert_file == None:
        cert_file = True

    # If ssl_verify is explicitly false then ignore ssl certificate even if cert_file is set
    if not ssl_verify:
        cert_file = False
   
    r = requests.post(url=url,data=iam_api_key,verify=cert_file)

    if r.status_code == 401:
        raise ConjurIAMAuthnException()
    return r.text

"""
If using IAM roles with conjur via the python3 api client use this function.
The client will not support auto-refreshing of token when using iam authentication so it is recommended to call this method everytime you make a client request.
An issue/enhancement has ben created on the conjur-python3-api github to address this issue however this is a work around for the time being.
"""
def create_conjur_iam_client(appliance_url, account, service_id, host_id, cert_file, iam_role_name=None, access_key=None, secret_key=None, token=None, ssl_verify=True):
    appliance_url = appliance_url.rstrip("/")
    # create our client with a placeholder api key
    connection_info = ConjurConnectionInfo(conjur_url=appliance_url,account=account,cert_file=cert_file)
    credentials = CredentialsData(username=host_id, api_key="placeholder", machine=appliance_url)
    credentials_provider = SimpleCredentialsProvider()
    credentials_provider.save(credentials)
    del credentials
    authn_provider = AuthnAuthenticationStrategy(credentials_provider)
    ssl_verification_mode=SslVerificationMode.CA_BUNDLE

    if cert_file is None:
        ssl_verification_mode=SslVerificationMode.INSECURE

    client = Client(connection_info,
                authn_strategy=authn_provider,
                ssl_verification_mode=ssl_verification_mode, async_mode=False)

    # telemetry changes
    #latest_version = Client.get_latest_version(os.path.join(os.path.dirname(__file__),'CHANGELOG.md'))
    #client.set_top_source_name("cour_iam_client/"+latest_version)

    # now obtain the iam session_token
    session_token = get_conjur_iam_session_token(appliance_url, account, service_id, host_id, cert_file, iam_role_name, access_key, secret_key, token, ssl_verify)

    # override the _api_token with the token created in get_conjur_iam_session_token
    client._api._api_token = session_token
    client._api.api_token_expiration = datetime.datetime.now() + timedelta(minutes=8)

    return client

def create_conjur_iam_client_from_env(iam_role_name=None, access_key=None, secret_key=None, token=None, ssl_verify=True):
    try:
        appliance_url = os.environ['CONJUR_APPLIANCE_URL']
        account = os.environ['CONJUR_ACCOUNT']
        service_id = os.environ['AUTHN_IAM_SERVICE_ID']
        host_id = os.environ['CONJUR_AUTHN_LOGIN']
        cert_file = None
        if 'CONJUR_CERT_FILE' in os.environ:
            cert_file = os.environ['CONJUR_CERT_FILE']
        return create_conjur_iam_client(appliance_url, account, service_id, host_id, cert_file, iam_role_name, access_key, secret_key, token, ssl_verify)
    except KeyError as e:
        raise KeyError("Failed to retrieve environment variable: {}".format(e))


# Examples of using methods:
# get_conjur_iam_session_token(os.environ['CONJUR_APPLIANCE_URL'], os.environ['CONJUR_ACCOUNT'], os.environ['AUTHN_IAM_SERVICE_ID'], os.environ['CONJUR_AUTHN_LOGIN'], os.environ['CONJUR_CERT_FILE'])
# create_conjur_iam_client(os.environ['CONJUR_APPLIANCE_URL'], os.environ['CONJUR_ACCOUNT'], os.environ['AUTHN_IAM_SERVICE_ID'], os.environ['CONJUR_AUTHN_LOGIN'], os.environ['CONJUR_CERT_FILE'])
