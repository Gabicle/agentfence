from dataclasses import FrozenInstanceError
from typing import cast

import pytest

from agentfence import (
    ActorRecord,
    AuthorizationDenied,
    AuthorizationDecision,
    AuthorizationRequest,
    Gateway,
    InvalidProposal,
    ReportRecord,
    ResourceAttributes,
    SubjectAttributes,
    ToolProposal,
)

DECISION_ID = "0123456789abcdef0123456789abcdef"


class FakeAuthorizer:
    def __init__(self, decision: object) -> None:
        self.decision = decision
        self.requests: list[AuthorizationRequest] = []

    def authorize(self, request: AuthorizationRequest) -> AuthorizationDecision:
        self.requests.append(request)
        if isinstance(self.decision, Exception):
            raise self.decision
        return cast(AuthorizationDecision, self.decision)


@pytest.fixture
def records() -> tuple[dict[str, ActorRecord], dict[str, ReportRecord]]:
    actors = {"session-1": ActorRecord("alice", "eu-west", 3)}
    reports = {
        "quarterly": ReportRecord(
            "quarterly", "2026-q3", "eu-west", 2, "Q3 report"
        )
    }
    return actors, reports


def test_authorized_read_uses_canonical_request_and_executes_once(records) -> None:
    actors, reports = records
    authorizer = FakeAuthorizer(AuthorizationDecision(True, DECISION_ID, "authorization_allowed"))
    gateway = Gateway(actors, reports, authorizer)

    result = gateway.execute("session-1", ToolProposal("read_report", {"report_id": "quarterly"}))

    assert result == "Q3 report"
    assert gateway.execution_log == ("quarterly",)
    assert authorizer.requests == [
        AuthorizationRequest(
            subject_type="user",
            subject_id="alice",
            object_type="report",
            object_id="2026-q3",
            relation="viewer",
            subject_attributes=SubjectAttributes("eu-west", 3),
            resource_attributes=ResourceAttributes("eu-west", 2),
        )
    ]
    with pytest.raises(FrozenInstanceError):
        authorizer.requests[0].relation = "owner"
    with pytest.raises(FrozenInstanceError):
        authorizer.requests[0].subject_attributes.clearance_level = 10


def test_denial_prevents_execution(records) -> None:
    authorizer = FakeAuthorizer(AuthorizationDecision(False, DECISION_ID, "relationship_denied"))
    gateway = Gateway(*records, authorizer)

    with pytest.raises(AuthorizationDenied, match="denied"):
        gateway.execute("session-1", ToolProposal("read_report", {"report_id": "quarterly"}))

    assert len(authorizer.requests) == 1
    assert gateway.execution_log == ()


def test_authorizer_exception_fails_closed(records) -> None:
    authorizer = FakeAuthorizer(RuntimeError("unavailable"))
    gateway = Gateway(*records, authorizer)

    with pytest.raises(AuthorizationDenied, match="authorization failed"):
        gateway.execute("session-1", ToolProposal("read_report", {"report_id": "quarterly"}))

    assert len(authorizer.requests) == 1
    assert gateway.execution_log == ()


@pytest.mark.parametrize("decision", [1, "true"])
def test_non_boolean_truthy_authorizer_response_fails_closed(records, decision) -> None:
    authorizer = FakeAuthorizer(
        AuthorizationDecision(decision, DECISION_ID, "authorization_allowed")
    )
    gateway = Gateway(*records, authorizer)

    with pytest.raises(AuthorizationDenied, match="denied"):
        gateway.execute("session-1", ToolProposal("read_report", {"report_id": "quarterly"}))

    assert len(authorizer.requests) == 1
    assert gateway.execution_log == ()


@pytest.mark.parametrize(
    "decision",
    [
        AuthorizationDecision(True),
        AuthorizationDecision(True, "bad-id", "authorization_allowed"),
        AuthorizationDecision(True, DECISION_ID, "relationship_denied"),
        AuthorizationDecision(True, DECISION_ID, "authorization_allowed", "invalid_response"),
        True,
    ],
)
def test_invalid_structured_approval_never_executes(records, decision) -> None:
    authorizer = FakeAuthorizer(decision)
    gateway = Gateway(*records, authorizer)

    with pytest.raises(AuthorizationDenied, match="denied"):
        gateway.execute("session-1", ToolProposal("read_report", {"report_id": "quarterly"}))

    assert len(authorizer.requests) == 1
    assert gateway.execution_log == ()


@pytest.mark.parametrize(
    "override",
    [
        {"subject_type": "service_account"},
        {"subject_id": "admin"},
        {"object_type": "document"},
        {"object_id": "public"},
        {"relation": "owner"},
        {"subject_attributes": {"clearance_level": 99}},
        {"resource_attributes": {"sensitivity_level": 0}},
    ],
)
def test_proposal_cannot_override_trusted_authorization_fields(records, override) -> None:
    authorizer = FakeAuthorizer(AuthorizationDecision(True, DECISION_ID, "authorization_allowed"))
    gateway = Gateway(*records, authorizer)
    proposal = ToolProposal("read_report", {"report_id": "quarterly", **override})

    with pytest.raises(InvalidProposal, match="only report_id"):
        gateway.execute("session-1", proposal)

    assert authorizer.requests == []
    assert gateway.execution_log == ()


@pytest.mark.parametrize(
    "proposal",
    [
        ToolProposal("delete_report", {"report_id": "quarterly"}),
        ToolProposal("read_report", {}),
        ToolProposal("read_report", {"report_id": {"id": "quarterly"}}),
    ],
)
def test_unsupported_or_malformed_proposal_never_executes(records, proposal) -> None:
    authorizer = FakeAuthorizer(AuthorizationDecision(True, DECISION_ID, "authorization_allowed"))
    gateway = Gateway(*records, authorizer)

    with pytest.raises(InvalidProposal):
        gateway.execute("session-1", proposal)

    assert authorizer.requests == []
    assert gateway.execution_log == ()


def test_unknown_actor_or_report_never_executes(records) -> None:
    authorizer = FakeAuthorizer(AuthorizationDecision(True, DECISION_ID, "authorization_allowed"))
    gateway = Gateway(*records, authorizer)

    with pytest.raises(InvalidProposal):
        gateway.execute("unknown-session", ToolProposal("read_report", {"report_id": "quarterly"}))
    with pytest.raises(InvalidProposal):
        gateway.execute("session-1", ToolProposal("read_report", {"report_id": "unknown"}))

    assert authorizer.requests == []
    assert gateway.execution_log == ()


def test_proposal_and_trusted_records_are_snapshotted(records) -> None:
    actors, reports = records
    arguments = {"report_id": "quarterly"}
    proposal = ToolProposal("read_report", arguments)
    gateway = Gateway(
        actors, reports, FakeAuthorizer(AuthorizationDecision(True, DECISION_ID, "authorization_allowed"))
    )

    arguments["report_id"] = "unknown"
    actors.clear()
    reports.clear()

    with pytest.raises(FrozenInstanceError):
        proposal.name = "delete_report"
    with pytest.raises(TypeError):
        proposal.arguments["report_id"] = "unknown"
    assert gateway.execute("session-1", proposal) == "Q3 report"
    assert gateway.execution_log == ("quarterly",)
