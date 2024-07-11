import pytest

from unittest import (
    TestCase,
    mock,
)

from ncanode_client import NCANodeClient


@mock.patch("ncanode_client.requests.post")
@mock.patch("ncanode_client.logger.error")
class TestNCANodeClient(TestCase):
    def test_init_default(self, _, __):
        client = NCANodeClient()
        self.assertEqual(client.base_url, "http://localhost:14579")
        self.assertEqual(client.timeout, 30)

    def test_init_w_values(self, _, __):
        client = NCANodeClient("http://a.com", 10)
        self.assertEqual(client.base_url, "http://a.com")
        self.assertEqual(client.timeout, 10)

    def test_handle_response(self, p_error, __):
        client = NCANodeClient()
        response = mock.Mock()

        response.json.return_value = {"status": 200}
        response.status_code = 200
        self.assertEqual(client.handle_response(response), (True, {"status": 200}))

        response.json.return_value = {"status": 400, "message": "error"}
        response.status_code = 400
        self.assertEqual(client.handle_response(response), (False, "error"))

        response.status_code = 400
        response.json.return_value = {"status": 400}
        self.assertEqual(client.handle_response(response), (False, "Unknown error"))

        p_error.assert_has_calls(
            [
                mock.call("error", extra={"status": 400}),
                mock.call("Unknown error at NCANodeClient", extra={"status": 400}),
            ]
        )

    def test_xml_verify_default(self, _, p_post):
        client = NCANodeClient()
        client.xml_verify("some_xml")
        p_post.assert_called_once_with(
            "http://localhost:14579/xml/verify",
            json={"revocationCheck": [], "xml": "some_xml"},
            timeout=30,
        )

    def test_xml_verify_ok(self, _, p_post):
        client = NCANodeClient()
        client.xml_verify("some_xml", verify_ocsp=True, verify_crl=True)
        p_post.assert_called_once_with(
            "http://localhost:14579/xml/verify",
            json={"revocationCheck": ["OCSP", "CRL"], "xml": "some_xml"},
            timeout=30,
        )

    def test_xml_sign_default(self, _, p_post):
        client = NCANodeClient()
        client.xml_sign("some_xml", key="key", password="password")
        p_post.assert_called_once_with(
            "http://localhost:14579/xml/sign",
            json={
                "xml": "some_xml",
                "signers": [
                    {
                        "key": "key",
                        "password": "password",
                        "keyAlias": None,
                    }
                ],
                "clearSignatures": False,
                "trimXml": False,
            },
            timeout=30,
        )

    def test_xml_sign_w_signers(self, _, p_post):
        client = NCANodeClient()
        client.xml_sign(
            "some_xml",
            signers=[
                {
                    "key": "key",
                    "password": "password",
                    "keyAlias": "key_alias",
                }
            ],
            clear_signatures=True,
            trim_xml=True,
        )
        p_post.assert_called_once_with(
            "http://localhost:14579/xml/sign",
            json={
                "xml": "some_xml",
                "signers": [
                    {
                        "key": "key",
                        "password": "password",
                        "keyAlias": "key_alias",
                    }
                ],
                "clearSignatures": True,
                "trimXml": True,
            },
            timeout=30,
        )

    def test_x509_info_default(self, _, p_post):
        client = NCANodeClient()
        client.x509_info("x509")
        p_post.assert_called_once_with(
            "http://localhost:14579/x509/info",
            json={"revocationCheck": [], "certs": ["x509"]},
            timeout=30,
        )

    def test_x509_info_ok(self, _, p_post):
        client = NCANodeClient()
        client.x509_info("x509", verify_ocsp=True, verify_crl=True)
        p_post.assert_called_once_with(
            "http://localhost:14579/x509/info",
            json={"revocationCheck": ["OCSP", "CRL"], "certs": ["x509"]},
            timeout=30,
        )

    def test_wsse_sign_default(self, _, p_post):
        client = NCANodeClient()
        client.wsse_sign("some_xml", key="key", password="password")
        p_post.assert_called_once_with(
            "http://localhost:14579/wsse/sign",
            json={
                "xml": "some_xml",
                "key": "key",
                "password": "password",
                "keyAlias": None,
                "trimXml": False,
            },
            timeout=30,
        )

    def test_cms_sign_default(self, _, p_post):
        client = NCANodeClient()
        client.cms_sign("some_data", key="key", password="password")
        p_post.assert_called_once_with(
            "http://localhost:14579/cms/sign",
            json={
                "data": "some_data",
                "signers": [
                    {
                        "key": "key",
                        "password": "password",
                        "keyAlias": None,
                    }
                ],
                "withTsp": True,
                "tsaPolicy": "TSA_GOST_POLICY",
                "detached": False,
            },
            timeout=30,
        )

    def test_cms_sign_w_signers(self, _, p_post):
        client = NCANodeClient()
        client.cms_sign(
            "some_data",
            signers=[
                {
                    "key": "key",
                    "password": "password",
                    "keyAlias": "key_alias",
                }
            ],
            with_tsp=False,
            tsa_policy="asdf",
            detached=True,
        )
        p_post.assert_called_once_with(
            "http://localhost:14579/cms/sign",
            json={
                "data": "some_data",
                "signers": [
                    {
                        "key": "key",
                        "password": "password",
                        "keyAlias": "key_alias",
                    }
                ],
                "withTsp": False,
                "tsaPolicy": "asdf",
                "detached": True,
            },
            timeout=30,
        )
