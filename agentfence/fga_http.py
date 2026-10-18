"""Check-only HTTP authorizer for the pinned fga-dotnet permission contract."""

from __future__ import annotations

import base64
import binascii
import http.client
import ipaddress
import json
import math
import os
import socket
import time
from typing import Mapping
from urllib.parse import urlsplit

from .gateway import AuthorizationDecision, AuthorizationRequest, _valid_decision_id


MAX_RESPONSE_BYTES = 65_536


class ConfigurationError(ValueError):
    """The trusted authorization service configuration is invalid."""


class FgaHttpAuthorizer:
    """Make one bounded permission check; never follow redirects or retry."""

    def __init__(
        self,
        service_url: str,
        check_key: str,
        *,
        connect_timeout: float = 2.0,
        read_timeout: float = 2.0,
        request_timeout: float = 5.0,
    ) -> None:
        if not isinstance(check_key, str) or not check_key:
            raise ConfigurationError("FGA_CHECK_API_KEY is required.")
        try:
            decoded_key = base64.b64decode(check_key, validate=True)
        except (ValueError, binascii.Error):
            raise ConfigurationError("FGA_CHECK_API_KEY must encode 32 bytes.") from None
        if len(decoded_key) != 32 or len(set(decoded_key)) == 1:
            raise ConfigurationError("FGA_CHECK_API_KEY must encode a non-degenerate 32-byte key.")

        try:
            parsed = urlsplit(service_url)
            host = parsed.hostname
            port = parsed.port
        except (TypeError, ValueError):
            raise ConfigurationError("FGA_AUTHORIZATION_URL must be a service origin.") from None
        if (
            parsed.scheme not in ("http", "https")
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or port == 0
        ):
            raise ConfigurationError("FGA_AUTHORIZATION_URL must be a service origin.")
        if parsed.scheme == "http" and not _is_loopback(host):
            raise ConfigurationError("Plain HTTP is allowed only for a loopback service URL.")
        if any(
            type(value) not in (int, float) or not math.isfinite(value) or value <= 0
            for value in (connect_timeout, read_timeout, request_timeout)
        ):
            raise ConfigurationError("Authorization timeouts must be positive finite seconds.")

        self._scheme = parsed.scheme
        self._host = host
        self._port = port
        self._key = check_key
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._request_timeout = request_timeout

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> FgaHttpAuthorizer:
        source = os.environ if environ is None else environ
        url = source.get("FGA_AUTHORIZATION_URL")
        key = source.get("FGA_CHECK_API_KEY")
        if not url or not key:
            raise ConfigurationError("FGA_AUTHORIZATION_URL and FGA_CHECK_API_KEY are required.")
        return cls(url, key)

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        connection: http.client.HTTPConnection | None = None
        deadline = time.monotonic() + self._request_timeout
        try:
            connection_type = (
                http.client.HTTPSConnection if self._scheme == "https" else http.client.HTTPConnection
            )
            connection = connection_type(
                self._host,
                self._port,
                timeout=min(self._connect_timeout, _remaining(deadline)),
            )
            connection.connect()
            sock = connection.sock
            if sock is None:
                raise OSError("Authorization connection is closed.")
            body = json.dumps(request.payload(), separators=(",", ":")).encode("utf-8")
            _set_socket_timeout(sock, self._read_timeout, deadline)
            connection.request(
                "POST",
                "/api/permissions/check",
                body=body,
                headers={
                    "Authorization": "ApiKey " + self._key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            _set_socket_timeout(sock, self._read_timeout, deadline)
            response = connection.getresponse()
            decision_id = _decision_id(response)
            if response.status != 200:
                return AuthorizationDecision(False, decision_id, failure=f"http_{response.status}")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return AuthorizationDecision(False, decision_id, failure="invalid_response")

            chunks: list[bytes] = []
            size = 0
            while True:
                _set_socket_timeout(sock, self._read_timeout, deadline)
                chunk = response.read1(min(4096, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    return AuthorizationDecision(False, decision_id, failure="invalid_response")
                chunks.append(chunk)
            if response.length not in (None, 0):
                return AuthorizationDecision(False, decision_id, failure="invalid_response")
            try:
                data = json.loads(b"".join(chunks).decode("utf-8"))
            except (ValueError, UnicodeError):
                return AuthorizationDecision(False, decision_id, failure="invalid_response")
            return _interpret_response(data, decision_id)
        except Exception:
            # Hide transport details, including any URL or credential text.
            return AuthorizationDecision(False, failure="transport_error")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Authorization request timed out.")
    return remaining


def _set_socket_timeout(sock: socket.socket, read_timeout: float, deadline: float) -> None:
    sock.settimeout(min(read_timeout, _remaining(deadline)))


def _decision_id(response: http.client.HTTPResponse) -> str | None:
    values = response.headers.get_all("X-Authorization-Decision-Id", [])
    return values[0] if len(values) == 1 and _valid_decision_id(values[0]) else None


def _interpret_response(data: object, decision_id: str | None) -> AuthorizationDecision:
    if not isinstance(data, dict) or decision_id is None:
        return AuthorizationDecision(False, decision_id, failure="invalid_response")
    allowed = data.get("allowed")
    reason = data.get("reason")
    code = data.get("reasonCode")
    if type(allowed) is not bool or not isinstance(reason, str) or not reason.strip():
        return AuthorizationDecision(False, decision_id, failure="invalid_response")
    if allowed is True and code == "authorization_allowed":
        return AuthorizationDecision(True, decision_id, code)
    if allowed is False and code in ("relationship_denied", "required_abac_denied"):
        return AuthorizationDecision(False, decision_id, code)
    return AuthorizationDecision(False, decision_id, failure="invalid_response")
