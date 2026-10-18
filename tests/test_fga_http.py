import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import time

import pytest

from agentfence import (
    ActorRecord,
    AuthorizationDecision,
    AuthorizationDenied,
    ConfigurationError,
    FgaHttpAuthorizer,
    Gateway,
    ReportRecord,
    ToolProposal,
)


DECISION_ID = "0123456789abcdef0123456789abcdef"
CHECK_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
ALLOW = {"allowed": True, "reason": "Allowed via tuple", "reasonCode": "authorization_allowed"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        raw_body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.seen.append((self.path, dict(self.headers), json.loads(raw_body)))
        self.server.request_seen.set()
        if self.server.block_response:
            self.server.release.wait(2)
        self.send_response(self.server.status)
        for name, value in self.server.response_headers.items():
            self.send_header(name, value)
        self.end_headers()
        try:
            if self.server.chunk_delay:
                for chunk in self.server.body:
                    self.wfile.write(bytes((chunk,)))
                    self.wfile.flush()
                    time.sleep(self.server.chunk_delay)
            else:
                self.wfile.write(self.server.body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, _format: str, *args: object) -> None:
        pass


@pytest.fixture
def mock_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.seen = []
    server.status = 200
    server.body = json.dumps(ALLOW).encode()
    server.response_headers = {
        "Content-Type": "application/json",
        "X-Authorization-Decision-Id": DECISION_ID,
    }
    server.block_response = False
    server.chunk_delay = 0
    server.request_seen = threading.Event()
    server.release = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class RecordingAuthorizer:
    def __init__(self, inner: FgaHttpAuthorizer) -> None:
        self.inner = inner
        self.decisions: list[AuthorizationDecision] = []

    def authorize(self, request) -> AuthorizationDecision:
        decision = self.inner.authorize(request)
        self.decisions.append(decision)
        return decision


def gateway_for(mock_server, *, read_timeout=0.5, request_timeout=2.0):
    client = FgaHttpAuthorizer(
        f"http://127.0.0.1:{mock_server.server_port}",
        CHECK_KEY,
        connect_timeout=0.5,
        read_timeout=read_timeout,
        request_timeout=request_timeout,
    )
    authorizer = RecordingAuthorizer(client)
    gateway = Gateway(
        {"session-1": ActorRecord("alice", "eu-west", 3)},
        {"quarterly": ReportRecord("quarterly", "2026-q3", "eu-west", 2, "Q3 report")},
        authorizer,
    )
    return gateway, authorizer


def execute(gateway: Gateway) -> str:
    return gateway.execute("session-1", ToolProposal("read_report", {"report_id": "quarterly"}))


def test_valid_approval_sends_exact_trusted_payload_and_executes_once(mock_server) -> None:
    gateway, authorizer = gateway_for(mock_server)

    assert execute(gateway) == "Q3 report"

    assert gateway.execution_log == ("quarterly",)
    assert authorizer.decisions == [AuthorizationDecision(True, DECISION_ID, "authorization_allowed")]
    assert len(mock_server.seen) == 1
    path, headers, payload = mock_server.seen[0]
    assert path == "/api/permissions/check"
    assert headers["Authorization"] == "ApiKey " + CHECK_KEY
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
    assert payload == {
        "subjectType": "user",
        "subjectId": "alice",
        "objectType": "report",
        "objectId": "2026-q3",
        "relation": "viewer",
        "subjectAttributes": {
            "subjectType": "user",
            "subjectId": "alice",
            "region": "eu-west",
            "clearanceLevel": 3,
        },
        "resourceAttributes": {
            "resourceType": "report",
            "resourceId": "2026-q3",
            "region": "eu-west",
            "sensitivityLevel": 2,
        },
    }


def test_environment_configuration_supplies_check_credentials(mock_server) -> None:
    authorizer = FgaHttpAuthorizer.from_environment(
        {
            "FGA_AUTHORIZATION_URL": f"http://127.0.0.1:{mock_server.server_port}",
            "FGA_CHECK_API_KEY": CHECK_KEY,
        }
    )
    gateway = Gateway(
        {"session-1": ActorRecord("alice", "eu-west", 3)},
        {"quarterly": ReportRecord("quarterly", "2026-q3", "eu-west", 2, "Q3 report")},
        authorizer,
    )

    assert execute(gateway) == "Q3 report"
    assert mock_server.seen[0][1]["Authorization"] == "ApiKey " + CHECK_KEY
    assert len(mock_server.seen) == 1
    assert gateway.execution_log == ("quarterly",)


@pytest.mark.parametrize("reason_code", ["relationship_denied", "required_abac_denied"])
def test_documented_denials_never_execute(mock_server, reason_code) -> None:
    mock_server.body = json.dumps(
        {"allowed": False, "reason": "Denied", "reasonCode": reason_code}
    ).encode()
    gateway, authorizer = gateway_for(mock_server)

    with pytest.raises(AuthorizationDenied):
        execute(gateway)

    assert authorizer.decisions == [AuthorizationDecision(False, DECISION_ID, reason_code)]
    assert gateway.execution_log == ()
    assert len(mock_server.seen) == 1


@pytest.mark.parametrize(
    "body, header_change",
    [
        (b"{", None),
        (json.dumps(ALLOW).encode(), ("X-Authorization-Decision-Id", "bad-id")),
        (json.dumps(ALLOW).encode(), ("X-Authorization-Decision-Id", None)),
        (json.dumps({**ALLOW, "reasonCode": "relationship_denied"}).encode(), None),
        (json.dumps({"allowed": False, "reason": "Denied", "reasonCode": "authorization_allowed"}).encode(), None),
        (json.dumps({**ALLOW, "allowed": 1}).encode(), None),
        (json.dumps({**ALLOW, "allowed": "true"}).encode(), None),
        (json.dumps({**ALLOW, "reason": " "}).encode(), None),
        (json.dumps(ALLOW).encode(), ("Content-Type", "text/plain")),
        (b" " * 65_537, None),
        (json.dumps(ALLOW).encode(), ("Content-Length", "1000")),
    ],
)
def test_invalid_responses_fail_closed(mock_server, body, header_change) -> None:
    mock_server.body = body
    if header_change is not None:
        name, value = header_change
        if value is None:
            del mock_server.response_headers[name]
        else:
            mock_server.response_headers[name] = value
    gateway, authorizer = gateway_for(mock_server)

    with pytest.raises(AuthorizationDenied):
        execute(gateway)

    assert authorizer.decisions[0].approved is False
    assert authorizer.decisions[0].failure == "invalid_response"
    assert gateway.execution_log == ()
    assert len(mock_server.seen) == 1


@pytest.mark.parametrize("status", [400, 401, 403, 500, 302])
def test_non_200_and_redirects_fail_closed_without_retry(mock_server, status) -> None:
    mock_server.status = status
    mock_server.response_headers["Location"] = "/api/permissions/check"
    gateway, authorizer = gateway_for(mock_server)

    with pytest.raises(AuthorizationDenied):
        execute(gateway)

    assert authorizer.decisions == [AuthorizationDecision(False, DECISION_ID, failure=f"http_{status}")]
    assert gateway.execution_log == ()
    assert len(mock_server.seen) == 1


def test_read_timeout_fails_closed(mock_server) -> None:
    mock_server.block_response = True
    gateway, authorizer = gateway_for(mock_server, read_timeout=0.1, request_timeout=0.3)

    with pytest.raises(AuthorizationDenied):
        execute(gateway)

    assert mock_server.request_seen.wait(1)
    assert authorizer.decisions == [AuthorizationDecision(False, failure="transport_error")]
    assert gateway.execution_log == ()
    assert len(mock_server.seen) == 1


def test_overall_request_deadline_fails_closed_during_slow_body(mock_server) -> None:
    mock_server.body = b"{}"
    mock_server.chunk_delay = 0.3
    gateway, authorizer = gateway_for(mock_server, read_timeout=0.5, request_timeout=0.12)

    with pytest.raises(AuthorizationDenied):
        execute(gateway)

    assert authorizer.decisions == [AuthorizationDecision(False, failure="transport_error")]
    assert gateway.execution_log == ()
    assert len(mock_server.seen) == 1


def test_connection_failure_fails_closed(mock_server) -> None:
    with socket.socket() as reserved_port:
        reserved_port.bind(("127.0.0.1", 0))
        authorizer = RecordingAuthorizer(
            FgaHttpAuthorizer(
                f"http://127.0.0.1:{reserved_port.getsockname()[1]}",
                CHECK_KEY,
                connect_timeout=0.1,
                read_timeout=0.1,
                request_timeout=0.3,
            )
        )
        gateway = Gateway(
            {"session-1": ActorRecord("alice", "eu-west", 3)},
            {"quarterly": ReportRecord("quarterly", "2026-q3", "eu-west", 2, "Q3 report")},
            authorizer,
        )
        with pytest.raises(AuthorizationDenied):
            execute(gateway)

    assert authorizer.decisions == [AuthorizationDecision(False, failure="transport_error")]
    assert gateway.execution_log == ()
    assert mock_server.seen == []


def test_configuration_is_required_and_never_reveals_the_credential() -> None:
    assert isinstance(
        FgaHttpAuthorizer.from_environment(
            {"FGA_AUTHORIZATION_URL": "https://fga.example", "FGA_CHECK_API_KEY": CHECK_KEY}
        ),
        FgaHttpAuthorizer,
    )
    with pytest.raises(ConfigurationError):
        FgaHttpAuthorizer.from_environment({})
    invalid = [
        ("http://example.com", CHECK_KEY),
        ("http://127.0.0.1/path", CHECK_KEY),
        ("http://user:secret@127.0.0.1", CHECK_KEY),
        ("http://127.0.0.1", "invalid"),
    ]
    for url, key in invalid:
        with pytest.raises(ConfigurationError) as error:
            FgaHttpAuthorizer(url, key)
        assert CHECK_KEY not in str(error.value)
        assert "secret" not in str(error.value)
    with pytest.raises(ConfigurationError):
        FgaHttpAuthorizer("http://127.0.0.1", CHECK_KEY, request_timeout=0)
