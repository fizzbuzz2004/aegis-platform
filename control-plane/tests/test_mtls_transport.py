import asyncio
import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from starlette.requests import Request
from uvicorn.protocols.http.h11_impl import H11Protocol

from app.core.mtls import (
    MTLSH11Protocol,
    PEER_CERTIFICATE_STATE_KEY,
    certificate_fingerprint,
    get_client_certificate_fingerprint,
)


def make_client_certificate_der():
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-agent")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.DER)


class FakeSSLObject:
    def __init__(self, certificate_der):
        self.certificate_der = certificate_der

    def getpeercert(self, binary_form=False):
        return self.certificate_der if binary_form else {}


class FakeTransport:
    def __init__(self, ssl_object):
        self.ssl_object = ssl_object

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self.ssl_object
        return default


def test_protocol_copies_peer_der_from_ssl_transport(monkeypatch):
    certificate_der = make_client_certificate_der()
    monkeypatch.setattr(H11Protocol, "connection_made", lambda self, transport: None)
    protocol = MTLSH11Protocol.__new__(MTLSH11Protocol)
    protocol.app_state = {}

    protocol.connection_made(FakeTransport(FakeSSLObject(certificate_der)))

    assert protocol.app_state[PEER_CERTIFICATE_STATE_KEY] == certificate_der


def test_request_fingerprint_comes_from_socket_state_not_headers(monkeypatch):
    certificate_der = make_client_certificate_der()
    monkeypatch.setattr("app.core.mtls.settings.AEGIS_MTLS_ENABLED", True)
    request = Request({
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/api/v1/sync/results",
        "raw_path": b"/api/v1/sync/results",
        "query_string": b"",
        "headers": [(b"x-forwarded-client-cert", b"forged-certificate")],
        "client": ("127.0.0.1", 40000),
        "server": ("127.0.0.1", 8000),
        "state": {PEER_CERTIFICATE_STATE_KEY: certificate_der},
    })

    fingerprint = asyncio.run(get_client_certificate_fingerprint(request))

    assert fingerprint == hashlib.sha256(certificate_der).hexdigest()
    assert certificate_fingerprint(certificate_der) == fingerprint
