# conjur-authn-iam-client-python
Get an IAM signed request used for Conjur authentication or instantiate a Conjur SDK Python3 client using IAM authentication.
- ![](https://img.shields.io/badge/Certification%20Level-Community-28A745?link=https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md)

## Requirements
- Conjur OSS v1+
- DAP v10+
- python >= 3.6
- summon >= 0.6.9

## Installation

### From source
```bash
$ pip3 install --user conjur-client
$ git clone https://github.com/cyberark/conjur-authn-iam-client-python.git
$ cd conjur-authn-iam-client-python; pip3 install --user .
```

## Usage Instructions

#### create_conjur_iam_api_key

This function returns a JSON-formatted [AWS signature](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) header that can be used to authenticate to Conjur when using the IAM authenticator.

```python
>>> from conjur_iam_client import *
>>> conjur_api_key = create_conjur_iam_api_key()
```

#### get_conjur_iam_session_token

This function uses the `create_conjur_iam_api_key` method to retrieve the AWS signature header, uses the header to authenticate to the Conjur API, and returns a Conjur [access token](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/Authentication-new.htm#Accesstokens).

```python
from conjur_iam_client import *
appliance_url = 'https://conjur.yourorg.com'
service_id = 'dev'
username = 'host/cust-portal/<aws-account-id>/<iam-role-name>'
cert_file = 'conjur-cert.pem'
conjur_account = 'dev'
conjur_session_token = get_conjur_iam_session_token(appliance_url, conjur_account, service_id, username, cert_file)
```

#### create_conjur_iam_client

This function will retrieve the session token from the method above and will initiate a conjur client for you. The conjur client returned can be found https://github.com/cyberark/conjur-api-python3. The token will not be refreshed within the client so the client can only be used for 5-8 min. After this time another client must be initiliazed with this method

```python
from conjur_iam_client import *
appliance_url = 'https://conjur.yourorg.com'
service_id = 'dev'
username = 'host/cust-portal/<aws-account-id>/<iam-role-name>'
cert_file = 'conjur-cert.pem'
conjur_account = 'dev'
conjur_client = create_conjur_iam_client(appliance_url, conjur_account, service_id, username, cert_file)
conjur_client.list() # This will return a list of all the resource you have access to. See https://github.com/cyberark/conjur-api-python3 for all of the methods this client supports.
```

#### create_conjur_iam_client_from_env

This function returns a client exactly like the function above. However instead of providing all of the parameters within the function it will read the parameters from the environment variables mentioned in the 'Setting environment variables' section.

```python
from conjur_iam_client import *
conjur_client = create_conjur_iam_client_from_env()
conjur_client.list() # This will return a list of all the resource you have access to. See https://github.com/cyberark/conjur-api-python3 for all of the methods this client supports.
```

## EC2 Usage
In this example we will be using the `create_conjur_iam_client_from_env()` function. It is assumed an IAM role is already associated with the ec2 instance.

#### Setting the environment variables
```bash
$ export CONJUR_APPLIANCE_URL=https://conjur.yourorg.com
$ export AUTHN_IAM_SERVICE_ID=dev
$ export CONJUR_AUTHN_LOGIN=host/cust-portal/<aws-account-id>/<iam-role-name>
$ export CONJUR_CERT_FILE=./conjur-dev.pem
$ export CONJUR_ACCOUNT=dev
```

#### Executing python script from the ec2 instance
```python3
from conjur import Client
from conjur_iam_client import create_conjur_iam_client_from_env

conjur_client = create_conjur_iam_client_from_env()
conjur_list = conjur_client.list()
```

## Lambda Usage
Since lambda cannot reach out to the AWS metadata url we have to slightly modify how we execute `create_conjur_iam_client_from_env()`. It is assumed an IAM role is already associated with the lambda function.

#### Lambda environment variables
```
CONJUR_APPLIANCE_URL=https://conjur.yourorg.com
AUTHN_IAM_SERVICE_ID=dev
CONJUR_AUTHN_LOGIN=host/cust-portal/<aws-account-id>/<iam-role-name>
CONJUR_CERT_FILE=./conjur-dev.pem
CONJUR_ACCOUNT=dev
IAM_ROLE_NAME=<iam-role-name>
# Depending if you want to ignore untrusted ssl certificate
IGNORE_SSL=<true or false>
```

#### Executing python script
The difference here is instead of having the client reach out to the metadata url and automatically obtain the keys and tokens required to authenticate. We are fetching these and pushing them into the `create_conjur_iam_client_from_env()` function.
```python3
from conjur import Client
from conjur_iam_client import create_conjur_iam_client_from_env
import os

def lambda_handler(event, context):
    iam_role_name=os.environ['IAM_ROLE_NAME']
    access_key=os.environ['AWS_ACCESS_KEY_ID']
    secret_key=os.environ['AWS_SECRET_ACCESS_KEY']
    token=os.environ['AWS_SESSION_TOKEN']
    conjur_client = create_conjur_iam_client_from_env(iam_role_name, access_key, secret_key, token)
    conjur_list = conjur_client.list()
    return {
        "list": conjur_list
    }
```

#### 
#### Example lambda function package
An example of a bundled lambda function can be found [here](https://github.com/cyberark/conjur-authn-iam-client-python/blob/master/lambda_function_package.zip). **If you are using a self signed certificate make sure to replace conjur-conjur.pem with your self signed cert!**

## Summon Usage
Summon usage has only been manually tested on an EC2 instance. With that being said make sure to set the [environment variables mentioned here](#ec2-usage). `iam_provider.py` is the summon provider. The `iam_provider.py` assumes python3 is installed on the EC2 instance. Example below:
```bash
# this should print out the environment variables 
# which should contain the password retrieved
summon -p ./iam_provider.py env

# using 'iam_provider.py' standalone
./iam_provider.py path/to/secret/goes/here
```

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions
of our development workflows, please see our [contributing guide](CONTRIBUTING.md).

## License

This repository is licensed under Apache License 2.0 - see [`LICENSE`](LICENSE) for more details.
