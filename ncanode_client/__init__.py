import requests
import logging

try:
    from django.conf import settings

    BASE_URL = getattr(settings, "NCANODE_BASE_URL", "http://localhost:14579")
    BASE_URL_V2 = getattr(settings, "NCANODE_BASE_URL_V2", "http://localhost:14578")
    TIMEOUT = getattr(settings, "NCANODE_TIMEOUT", 30)
except ImportError:
    BASE_URL = "http://localhost:14579"
    BASE_URL_V2 = "http://localhost:14578"
    TIMEOUT = 30

logger = logging.getLogger(__name__)


class NCANodeClient:
    def __init__(self, base_url=None, timeout=None, base_url_v2=None):
        self.base_url = base_url or BASE_URL
        self.base_url_v2 = base_url_v2 or BASE_URL_V2
        self.timeout = timeout or TIMEOUT

    def handle_response(self, response):
        response_json = response.json()
        if response.status_code == 200:
            return True, response_json
        else:
            if message := response_json.pop("message", None):
                logger.error(message, extra=response_json)
                return False, message
            else:
                logger.error("Unknown error at NCANodeClient", extra=response_json)
                return False, "Unknown error"

    def handle_response_v2(self, response):
        response_json = response.json()
        if response.status_code == 200 and response_json["status"] == 0:
            return True, response_json
        else:
            if message := response_json.pop("message", None):
                logger.error(message, extra=response_json)
                return False, message
            else:
                logger.error("Unknown error at NCANodeClient", extra=response_json)
                return False, "Unknown error"

    def xml_verify(self, xml, verify_ocsp=False, verify_crl=False):
        revocation_check = []

        if verify_ocsp:
            revocation_check.append("OCSP")

        if verify_crl:
            revocation_check.append("CRL")

        response = requests.post(
            f"{self.base_url}/xml/verify",
            json={
                "revocationCheck": revocation_check,
                "xml": xml,
            },
            timeout=self.timeout,
        )

        return self.handle_response(response)

    def xml_sign(
        self,
        xml,
        key=None,
        password=None,
        key_alias=None,
        signers=None,
        clear_signatures=False,
        trim_xml=False,
    ):
        assert key or signers, "Either key or signers must be provided"

        if signers is None:
            signers = [
                {
                    "key": key,
                    "password": password,
                    "keyAlias": key_alias,
                }
            ]

        response = requests.post(
            f"{self.base_url}/xml/sign",
            json={
                "xml": xml,
                "signers": signers,
                "clearSignatures": clear_signatures,
                "trimXml": trim_xml,
            },
            timeout=self.timeout,
        )

        return self.handle_response(response)

    def wsse_sign(
        self,
        xml,
        key,
        password,
        key_alias=None,
        trim_xml=False,
    ):
        data = {
            "key": key,
            "password": password,
            "keyAlias": key_alias,
            "xml": xml,
            "trimXml": trim_xml,
        }

        response = requests.post(
            f"{self.base_url}/wsse/sign",
            json=data,
            timeout=self.timeout,
        )

        return self.handle_response(response)

    def x509_info(self, certs=None, verify_ocsp=False, verify_crl=False):
        if isinstance(certs, str):
            certs = [certs]

        revocation_check = []

        if verify_ocsp:
            revocation_check.append("OCSP")

        if verify_crl:
            revocation_check.append("CRL")

        response = requests.post(
            f"{self.base_url}/x509/info",
            json={
                "revocationCheck": revocation_check,
                "certs": certs,
            },
            timeout=self.timeout,
        )

        return self.handle_response(response)

    def cms_sign(
        self,
        data,
        key=None,
        password=None,
        key_alias=None,
        signers=None,
        with_tsp=True,
        tsa_policy="TSA_GOST_POLICY",
        detached=False,
    ):
        assert key or signers, "Either key or signers must be provided"

        if signers is None:
            signers = [
                {
                    "key": key,
                    "password": password,
                    "keyAlias": key_alias,
                }
            ]

        response = requests.post(
            f"{self.base_url}/cms/sign",
            json={
                "data": data,
                "signers": signers,
                "withTsp": with_tsp,
                "tsaPolicy": tsa_policy,
                "detached": detached,
            },
            timeout=self.timeout,
        )

        return self.handle_response(response)

    def tsp_sign(self, data):
        response = requests.post(f"{self.base_url}/tsp/create", json={"xml": data})
        response_json = response.json()
        if response.status_code == 200 and response_json.get("message") == "OK":
            return True, response_json.get("token", "")
        else:
            if message := response_json.pop("message", None):
                logger.error(message, extra=response_json)
                return False, message
            else:
                logger.error("Unknown error at NCANodeClient", extra=response_json)
                return False, "Unknown error"

    def tsp_verify(self, data):
        response = requests.post(
            f"{self.base_url_v2}/tsp/sign",
            json={
                "version": "1.0",
                "method":"TSP.verify",
                "params": {
                    "cms": data
                }
            },
            timeout=self.timeout,
        )

        return self.handle_response_v2(response)
