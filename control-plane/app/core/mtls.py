from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from fastapi import HTTPException, Request, status
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from uvicorn import Config
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

from app.core.config import settings

PEER_CERTIFICATE_STATE_KEY = "aegis_verified_peer_certificate_der"


class MTLSH11Protocol(H11Protocol):
    def __init__(
        self,
        config: Config,
        server_state: ServerState,
        app_state: dict[str, Any],
        _loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        super().__init__(config, server_state, app_state, _loop)
        self.app_state = dict(app_state)

    def connection_made(self, transport: asyncio.Transport) -> None:
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        certificate_der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        self.app_state[PEER_CERTIFICATE_STATE_KEY] = certificate_der


def certificate_fingerprint(certificate_der: bytes) -> str:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as error:
        raise ValueError("TLS peer certificate is not valid DER X.509") from error
    return hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()


async def get_client_certificate_fingerprint(request: Request) -> str | None:
    if not settings.AEGIS_MTLS_ENABLED:
        return None
    certificate_der = request.scope.get("state", {}).get(PEER_CERTIFICATE_STATE_KEY)
    if not isinstance(certificate_der, bytes):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verified TLS client certificate is unavailable",
        )
    try:
        return certificate_fingerprint(certificate_der)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TLS client certificate is invalid",
        ) from None
