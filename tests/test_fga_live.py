"""Opt-in checks against a separately provisioned disposable fga-dotnet service."""

import json
import os
from pathlib import Path
import re
import socket

import pytest

from agentfence import (
    ActorRecord,
    AuthorizationDecision,
    AuthorizationDenied,
    AuthorizationRequest,
    ConfigurationError,
    FgaHttpAuthorizer,
    Gateway,
    ReportRecord,
    ToolProposal,
)


pytestmark = pytest.mark.live
ROOT = Path(__file__).resolve().parents[1]
DECISION_ID = re.compile(r"[0-9a-f]{32}\Z")
CASES = {
    "allowed": ("eu-west", 1),
    "region_denied": ("us-east", 1),
    "sensitivity_denied": ("eu-west", 3),
    "ungranted": ("eu-west", 1),
}


class RecordingAuthorizer:
    """Retain decisions for assertions without changing the production gateway."""

    def __init__(self, inner: FgaHttpAuthorizer) -> None:
        self.inner = inner
        self.decisions: list[AuthorizationDecision] = []

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        decision = self.inner.authorize(request)
        self.decisions.append(decision)
        return decision


def _load_manifest(path_string: str) -> dict:
    fixture_dir = (ROOT / ".fga-live").resolve()
    path = Path(path_string).resolve()
    if path.parent != fixture_dir or not path.name.startswith("fixture-"):
        pytest.fail("FGA_LIVE_MANIFEST must name a generated file inside .fga-live/.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pytest.fail("FGA_LIVE_MANIFEST is missing or invalid; run scripts/setup_fga_live.py.")
    if type(data) is not dict or set(data) != {"schema_version", "actor", "reports"}:
        pytest.fail("Invalid live fixture manifest structure.")
    actor = data["actor"]
    reports = data["reports"]
    if (
        data["schema_version"] != 1
        or type(actor) is not dict
        or set(actor) != {"id", "region", "clearance_level"}
        or not isinstance(actor["id"], str)
        or not actor["id"].startswith("agentfence-live-user-")
        or actor["region"] != "eu-west"
        or type(actor["clearance_level"]) is not int
        or actor["clearance_level"] != 2
        or type(reports) is not dict
        or set(reports) != set(CASES)
    ):
        pytest.fail("Invalid live fixture actor or report set.")
    identifiers = []
    for name, (region, sensitivity) in CASES.items():
        report = reports[name]
        if (
            type(report) is not dict
            or set(report) != {"id", "region", "sensitivity_level"}
            or not isinstance(report["id"], str)
            or not report["id"].startswith("agentfence-live-report-")
            or report["region"] != region
            or type(report["sensitivity_level"]) is not int
            or report["sensitivity_level"] != sensitivity
        ):
            pytest.fail("Invalid live fixture report attributes.")
        identifiers.append(report["id"])
    if len(set(identifiers)) != 4:
        pytest.fail("Live fixture report identifiers must be unique.")
    return data


@pytest.fixture(scope="module")
def live_fixture() -> tuple[dict, FgaHttpAuthorizer]:
    if os.environ.get("FGA_LIVE") != "1":
        pytest.skip("Set FGA_LIVE=1 to run the live fga-dotnet suite.")
    if os.environ.get("FGA_ADMIN_API_KEY"):
        pytest.fail("Unset FGA_ADMIN_API_KEY before running live checks.")
    path = os.environ.get("FGA_LIVE_MANIFEST")
    if not path:
        pytest.fail("FGA_LIVE_MANIFEST is required; run scripts/setup_fga_live.py first.")
    manifest = _load_manifest(path)
    try:
        client = FgaHttpAuthorizer.from_environment()
    except ConfigurationError as error:
        pytest.fail(f"Live check configuration is missing or invalid: {error}")
    return manifest, client


def _gateway(manifest: dict, client: FgaHttpAuthorizer, case: str):
    actor = manifest["actor"]
    report = manifest["reports"][case]
    report_id = report["id"]
    body = "synthetic report " + case
    recorder = RecordingAuthorizer(client)
    gateway = Gateway(
        {"trusted-session": ActorRecord(actor["id"], actor["region"], actor["clearance_level"])},
        {report_id: ReportRecord(report_id, report_id, report["region"], report["sensitivity_level"], body)},
        recorder,
    )
    return gateway, recorder, report_id, body


def _execute(gateway: Gateway, report_id: str) -> str:
    return gateway.execute("trusted-session", ToolProposal("read_report", {"report_id": report_id}))


def _decision(recorder: RecordingAuthorizer) -> AuthorizationDecision:
    if len(recorder.decisions) != 1:
        pytest.fail("Expected exactly one real HTTP authorization check.")
    decision = recorder.decisions[0]
    if decision.failure is not None:
        pytest.fail(f"Expected fga-dotnet check failed ({decision.failure}); verify the running disposable service and check key.")
    if decision.decision_id is None or DECISION_ID.fullmatch(decision.decision_id) is None:
        pytest.fail("Expected a valid authorization decision ID from fga-dotnet.")
    if os.environ.get("FGA_SHOW_DECISIONS") == "1":
        print(
            f"decision_id={decision.decision_id} "
            f"approved={decision.approved} reason_code={decision.reason_code}"
        )
    return decision


def test_granted_matching_report_executes_once(live_fixture) -> None:
    manifest, client = live_fixture
    gateway, recorder, report_id, body = _gateway(manifest, client, "allowed")

    try:
        result = _execute(gateway, report_id)
    except AuthorizationDenied:
        _decision(recorder)
        pytest.fail("Expected the granted matching report to be authorized.")

    assert result == body
    assert gateway.execution_log == (report_id,)
    decision = _decision(recorder)
    assert decision.approved is True
    assert decision.reason_code == "authorization_allowed"


@pytest.mark.parametrize(
    "case, reason_code",
    [
        ("region_denied", "required_abac_denied"),
        ("sensitivity_denied", "required_abac_denied"),
        ("ungranted", "relationship_denied"),
    ],
)
def test_denied_reports_never_execute(live_fixture, case, reason_code) -> None:
    manifest, client = live_fixture
    gateway, recorder, report_id, _body = _gateway(manifest, client, case)

    with pytest.raises(AuthorizationDenied):
        _execute(gateway, report_id)

    decision = _decision(recorder)
    assert decision.approved is False
    assert decision.reason_code == reason_code
    assert gateway.execution_log == ()


def test_unavailable_endpoint_fails_closed(live_fixture) -> None:
    manifest, _expected_client = live_fixture
    with socket.socket() as reserved_port:
        reserved_port.bind(("127.0.0.1", 0))
        unavailable = FgaHttpAuthorizer(
            f"http://127.0.0.1:{reserved_port.getsockname()[1]}",
            os.environ["FGA_CHECK_API_KEY"],
            connect_timeout=0.2,
            read_timeout=0.2,
            request_timeout=0.5,
        )
        gateway, recorder, report_id, _body = _gateway(manifest, unavailable, "allowed")
        with pytest.raises(AuthorizationDenied):
            _execute(gateway, report_id)

    assert recorder.decisions == [AuthorizationDecision(False, failure="transport_error")]
    assert gateway.execution_log == ()
