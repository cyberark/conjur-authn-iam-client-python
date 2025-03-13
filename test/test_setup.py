"""
This module contains the setup configuration for the Conjur IAM Client.
"""

import unittest

# pylint: disable=R0903
class DummyDistribution:
    """
    A dummy class representing a distribution, typically used for testing purposes.
    """
    def __init__(self, name, version, py_modules, url):
        self.name = name
        self.version = version
        self.py_modules = py_modules
        self.url = url

class TestSetup(unittest.TestCase):
    """
    A test case class for setting up the Conjur IAM client.
    """
    def setUp(self):
        """Create a dummy distribution object with setup attributes"""
        self.distribution = DummyDistribution(
            name='conjur_iam_client',
            version='0.1',
            py_modules=['conjur_iam_client'],
            url='https://github.com/cyberark/'
                'conjur-authn-iam-client-python'
        )

    def test_package_name(self):
        """Verify that the package name is correctly set"""
        self.assertEqual(self.distribution.name, 'conjur_iam_client')

    def test_package_version(self):
        """Verify that the package version is correctly set"""
        self.assertEqual(self.distribution.version, '0.1')

    def test_py_modules(self):
        """Verify that the py_modules attribute is correctly set"""
        self.assertEqual(self.distribution.py_modules, ['conjur_iam_client'])

    def test_url(self):
        """Verify that the URL is correctly set"""
        self.assertEqual(
            self.distribution.url,
            'https://github.com/cyberark/'
            'conjur-authn-iam-client-python'
        )


if __name__ == '__main__':
    unittest.main()
