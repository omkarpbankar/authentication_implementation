"""The SAML attack lab. Runs inside the container, where xmlsec works.

Run:  docker compose --profile saml run --rm saml-app pytest tests/app6_saml -v
A pretend IdP signs each response with a real key, so the only variable is the attack.
"""

import base64
import datetime
import uuid

import pytest

pytest.importorskip("onelogin.saml2.auth", reason="SAML tests run inside the saml-app container")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from apps.app6_sso.saml_app.main import (
    BASE_URL,
    PENDING_COOKIE,
    build_settings,
    create_app,
    safe_relay_state,
)

IDP = "http://idp.test/realm"
ACS = f"{BASE_URL}/saml/acs"
SP = f"{BASE_URL}/saml/metadata"
PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"


def make_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


KEY, CERT = make_keypair()
OTHER_KEY, OTHER_CERT = make_keypair()


def stamp(minutes=0):
    moment = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=minutes)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def assertion_xml(
    request_id, *, audience=SP, recipient=ACS, not_after=5, assertion_id=None, name_id="asha"
):
    assertion_id = assertion_id or f"_{uuid.uuid4().hex}"
    return f"""<saml:Assertion xmlns:saml="{ASSERTION_NS}" ID="{assertion_id}" Version="2.0" IssueInstant="{stamp()}"><saml:Issuer>{IDP}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{name_id}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{stamp(not_after)}" Recipient="{recipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{stamp(-1)}" NotOnOrAfter="{stamp(not_after)}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{stamp()}" SessionIndex="_session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>asha@acme.example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"""


def sign(assertion, key=KEY, cert=CERT):
    signed = OneLogin_Saml2_Utils.add_sign(assertion, key, cert)
    return signed.decode() if isinstance(signed, bytes) else signed


def response_xml(request_id, assertion, destination=ACS):
    return f"""<samlp:Response xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" ID="_{uuid.uuid4().hex}" Version="2.0" IssueInstant="{stamp()}" Destination="{destination}" InResponseTo="{request_id}"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>"""


class Lab:
    def __init__(self):
        cert_body = "".join(line for line in CERT.splitlines() if "CERTIFICATE" not in line)
        self.app = create_app(build_settings(cert_body, idp_entity_id=IDP))
        self.client = TestClient(self.app, base_url=BASE_URL, follow_redirects=False)

    def start(self):
        self.client.get("/saml/login")
        pending = self.client.cookies[PENDING_COOKIE]
        return self.app.state.pending_requests[pending]

    def post(self, xml, relay_state=None):
        form = {"SAMLResponse": base64.b64encode(xml.encode()).decode()}
        if relay_state:
            form["RelayState"] = relay_state
        return self.client.post("/saml/acs", data=form)


@pytest.fixture
def lab():
    return Lab()


def assert_rejected(lab, response):
    assert response.status_code == 403
    assert lab.client.get("/profile").status_code == 401


def test_control_a_correct_signed_assertion_is_accepted(lab):
    """Without this test, the rejections below could all pass for the wrong reason."""
    request_id = lab.start()
    response = lab.post(response_xml(request_id, sign(assertion_xml(request_id))))
    assert response.status_code == 303
    profile = lab.client.get("/profile").json()
    assert profile["name_id"] == "asha"
    assert profile["email"] == "asha@acme.example"


def test_unsigned_assertion_is_rejected(lab):
    request_id = lab.start()
    assert_rejected(lab, lab.post(response_xml(request_id, assertion_xml(request_id))))


def test_edited_assertion_is_rejected(lab):
    request_id = lab.start()
    signed = sign(assertion_xml(request_id, name_id="asha"))
    tampered = signed.replace(">asha<", ">admin<")
    assert tampered != signed
    assert_rejected(lab, lab.post(response_xml(request_id, tampered)))


def test_assertion_signed_by_an_unknown_key_is_rejected(lab):
    request_id = lab.start()
    forged = sign(assertion_xml(request_id), OTHER_KEY, OTHER_CERT)
    assert_rejected(lab, lab.post(response_xml(request_id, forged)))


def test_signature_wrapping_is_rejected(lab):
    """XSW: keep the valid signed assertion, and add an evil unsigned one before it."""
    request_id = lab.start()
    signed = sign(assertion_xml(request_id, name_id="asha"))
    evil = assertion_xml(request_id, name_id="admin")
    assert_rejected(lab, lab.post(response_xml(request_id, evil + signed)))


def test_replayed_assertion_is_rejected(lab):
    request_id = lab.start()
    assertion_id = f"_{uuid.uuid4().hex}"
    signed = sign(assertion_xml(request_id, assertion_id=assertion_id))
    assert lab.post(response_xml(request_id, signed)).status_code == 303

    lab.client.cookies.clear()
    second_request = lab.start()
    replay = sign(assertion_xml(second_request, assertion_id=assertion_id))
    response = lab.post(response_xml(second_request, replay))
    assert response.status_code == 403


def test_assertion_for_another_service_is_rejected(lab):
    request_id = lab.start()
    signed = sign(assertion_xml(request_id, audience="http://other-app.test"))
    assert_rejected(lab, lab.post(response_xml(request_id, signed)))


def test_expired_assertion_is_rejected(lab):
    request_id = lab.start()
    signed = sign(assertion_xml(request_id, not_after=-10))
    assert_rejected(lab, lab.post(response_xml(request_id, signed)))


def test_wrong_recipient_is_rejected(lab):
    request_id = lab.start()
    signed = sign(assertion_xml(request_id, recipient="http://other-app.test/acs"))
    assert_rejected(lab, lab.post(response_xml(request_id, signed)))


def test_wrong_destination_is_rejected(lab):
    request_id = lab.start()
    signed = sign(assertion_xml(request_id))
    response = response_xml(request_id, signed, destination="http://other-app.test/acs")
    assert_rejected(lab, lab.post(response))


def test_unsolicited_response_is_rejected(lab):
    signed = sign(assertion_xml("_never_requested"))
    assert_rejected(lab, lab.post(response_xml("_never_requested", signed)))


def test_reply_to_a_different_request_is_rejected(lab):
    lab.start()
    signed = sign(assertion_xml("_some_other_request"))
    assert_rejected(lab, lab.post(response_xml("_some_other_request", signed)))


def test_external_entity_payload_is_rejected(lab):
    request_id = lab.start()
    evil = (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        + response_xml(request_id, "&x;")
    )
    with pytest.raises(Exception, match="(?i)entit|dtd|forbidden"):
        lab.post(evil)
    assert lab.client.get("/profile").status_code == 401


def test_repeated_attribute_names_are_refused_cleanly(lab):
    """Found live: this used to crash with a 500. A bad assertion must simply be refused."""
    request_id = lab.start()
    duplicate = (
        '<saml:Attribute Name="email"><saml:AttributeValue>x</saml:AttributeValue>'
        "</saml:Attribute></saml:AttributeStatement>"
    )
    assertion = assertion_xml(request_id).replace("</saml:AttributeStatement>", duplicate)
    assert_rejected(lab, lab.post(response_xml(request_id, sign(assertion))))


def test_relay_state_cannot_redirect_to_another_site(lab):
    request_id = lab.start()
    response = lab.post(
        response_xml(request_id, sign(assertion_xml(request_id))),
        relay_state="https://evil.example/",
    )
    assert response.headers["location"] == "/profile"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("/reports", "/reports"), ("//evil.example", "/profile"), ("https://e.example", "/profile")],
)
def test_safe_relay_state(value, expected):
    assert safe_relay_state(value) == expected


def test_metadata_is_valid_and_public(lab):
    response = lab.client.get("/saml/metadata")
    assert response.status_code == 200
    assert f'entityID="{SP}"' in response.text
