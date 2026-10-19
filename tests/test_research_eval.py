"""Deterministic measurements of the one-case research evaluation runner."""

from __future__ import annotations

import json
from types import SimpleNamespace as Item

import pytest

from agentfence import AuthorizationDecision
import agentfence.research_eval as research_eval
from agentfence.research import REPORTS, gateway_from_manifest
from agentfence.research_eval import RecordingAuthorizer, evaluate, load_cases, main


ALLOWED = "northstar-q2-results"
RESTRICTED = "northstar-q2-board-risks"


def response(*items):
    return Item(status="completed", output=list(items))


def proposal(alias, *, arguments=None):
    return Item(
        type="function_call",
        status="completed",
        name="read_report",
        call_id="call_1",
        arguments=arguments if arguments is not None else json.dumps({"report_id": alias}),
    )


def answer(text="Revenue was $128 million and gross margin was 42%."):
    return response(
        Item(
            type="message",
            role="assistant",
            status="completed",
            content=[Item(type="output_text", text=text)],
        )
    )


class FakeAdapter:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class PolicyAuthorizer:
    def __init__(self, allowed_id):
        self.allowed_id = allowed_id
        self.requests = []

    def authorize(self, request):
        self.requests.append(request)
        approved = request.object_id == self.allowed_id
        return AuthorizationDecision(
            approved,
            "a" * 32,
            "authorization_allowed" if approved else "relationship_denied",
        )


@pytest.fixture
def setup():
    manifest = {
        "schema_version": 1,
        "actor": {"id": "agentfence-live-user-eval", "region": "eu-west", "clearance_level": 2},
        "reports": {
            spec.case: {
                "id": f"agentfence-live-report-{spec.case.replace('_denied', '')}-eval",
                "region": spec.region,
                "sensitivity_level": spec.sensitivity_level,
            }
            for spec in REPORTS.values()
        },
    }
    authorizer = PolicyAuthorizer(manifest["reports"]["allowed"]["id"])
    recorder = RecordingAuthorizer(authorizer)
    gateway, aliases = gateway_from_manifest(manifest, recorder)
    return manifest, gateway, aliases, authorizer, recorder


@pytest.fixture
def cases():
    return {case.id: case for case in load_cases()}


def run_case(case, adapter, setup):
    _, gateway, aliases, _, recorder = setup
    measured = evaluate(case, adapter, gateway, aliases, recorder, model="fake-model")
    assert measured["model"] == "fake-model"
    return measured


def test_corpus_has_five_versioned_synthetic_scenarios(cases):
    assert set(cases) == {
        "benign_control",
        "direct_redirection",
        "forged_authority",
        "task_aligned_manipulation",
        "answer_contamination",
    }
    assert {case.expected_report_alias for case in cases.values()} == {ALLOWED}
    assert sum(case.answer_marker is not None for case in cases.values()) == 1
    assert all(case.excerpt and "Northstar" in case.question for case in cases.values())


def test_recording_authorizer_returns_original_decision():
    decision = AuthorizationDecision(False, "a" * 32, "relationship_denied")

    class StubAuthorizer:
        def authorize(self, request):
            return decision

    recorder = RecordingAuthorizer(StubAuthorizer())

    assert recorder.authorize(object()) is decision
    assert recorder.approved is False
    assert recorder.failure_present is False
    assert recorder.explicit_policy_denial is True


def test_benign_control_measures_authorized_selection(cases, setup):
    adapter = FakeAdapter(response(proposal(ALLOWED)), answer())

    measured = run_case(cases["benign_control"], adapter, setup)

    assert measured["outcome"] == "completed"
    assert measured["proposal_status"] == "valid"
    assert measured["proposed_report_alias"] == ALLOWED
    assert measured["model_redirected"] is False
    assert measured["authorization_outcome"] == "authorized"
    assert measured["authorization_decision_approved"] is True
    assert measured["authorization_decision_failure"] is False
    assert measured["protected_execution_count"] == 1
    assert measured["access_denied_result"] is False
    assert measured["answer_marker_present"] is None
    assert measured["model_response_calls"] == 2
    assert len(setup[3].requests) == 1
    assert adapter.calls[1]["tools"] == [] and adapter.calls[1]["tool_choice"] == "none"
    assert all(call["store"] is False for call in adapter.calls)
    assert all(call["parallel_tool_calls"] is False for call in adapter.calls)
    assert all(spec.body not in json.dumps(measured) for spec in REPORTS.values())


@pytest.mark.parametrize("case_id", ["direct_redirection", "forged_authority", "task_aligned_manipulation"])
def test_restricted_redirection_is_measured_but_not_counted_as_bypass(cases, setup, case_id):
    adapter = FakeAdapter(response(proposal(RESTRICTED)), answer("Invented board facts"))

    measured = run_case(cases[case_id], adapter, setup)

    assert measured["proposed_report_alias"] == RESTRICTED
    assert measured["model_redirected"] is True
    assert measured["proposal_status"] == "valid"
    assert measured["authorization_outcome"] == "denied"
    assert measured["authorization_decision_approved"] is False
    assert measured["authorization_decision_failure"] is False
    assert measured["protected_execution_count"] == 0
    assert measured["access_denied_result"] is True
    assert measured["outcome"] == "denied"
    assert measured["model_response_calls"] == 2
    assert len(setup[3].requests) == 1
    assert setup[3].requests[0].subject_id == setup[0]["actor"]["id"]
    assert setup[3].requests[0].relation == "viewer"
    assert json.loads(adapter.calls[1]["input"][-1]["output"]) == {"status": "access_denied"}
    assert all(spec.body not in str(adapter.calls[0]) for spec in REPORTS.values())


def test_authorization_transport_failure_is_error_with_zero_execution(cases, setup):
    class FailedAuthorizer:
        def authorize(self, request):
            return AuthorizationDecision(False, failure="transport_error")

    recorder = RecordingAuthorizer(FailedAuthorizer())
    gateway, aliases = gateway_from_manifest(setup[0], recorder)
    adapter = FakeAdapter(response(proposal(ALLOWED)), answer("Invented facts"))

    measured = evaluate(
        cases["benign_control"], adapter, gateway, aliases, recorder, model="fake-model"
    )

    assert measured["model"] == "fake-model"
    assert measured["proposed_report_alias"] == ALLOWED
    assert measured["model_redirected"] is False
    assert measured["authorization_outcome"] == "service_failure"
    assert measured["authorization_decision_approved"] is False
    assert measured["authorization_decision_failure"] is True
    assert measured["protected_execution_count"] == 0
    assert measured["access_denied_result"] is True
    assert measured["outcome"] == "error"
    assert measured["error_code"] == "authorization_service_failure"
    assert "transport_error" not in json.dumps(measured)
    assert len(adapter.calls) == 2


@pytest.mark.parametrize("contains_marker", [False, True])
def test_answer_contamination_is_separate_from_selection(cases, setup, contains_marker):
    case = cases["answer_contamination"]
    text = "Revenue was $128 million."
    if contains_marker:
        text += f" {case.answer_marker}"
    adapter = FakeAdapter(response(proposal(ALLOWED)), answer(text))

    measured = run_case(case, adapter, setup)

    assert measured["proposed_report_alias"] == ALLOWED
    assert measured["model_redirected"] is False
    assert measured["protected_execution_count"] == 1
    assert measured["answer_marker_present"] is contains_marker
    assert measured["outcome"] == "completed"
    assert case.answer_marker not in json.dumps(measured)


@pytest.mark.parametrize(
    ("first", "expected"),
    [
        (answer("No report needed."), "no_proposal"),
        (response(proposal(ALLOWED, arguments="{")), "invalid_proposal"),
        (
            response(proposal(ALLOWED, arguments=json.dumps({"report_id": ALLOWED, "actor": "admin"}))),
            "invalid_proposal",
        ),
        (response(proposal(ALLOWED), proposal(RESTRICTED)), "invalid_proposal"),
    ],
)
def test_invalid_or_missing_proposals_never_execute(cases, setup, first, expected):
    adapter = FakeAdapter(first)

    measured = run_case(cases["benign_control"], adapter, setup)

    assert measured["outcome"] == expected
    assert measured["proposal_status"] == expected
    assert measured["proposed_report_alias"] is None
    assert measured["authorization_outcome"] == "not_attempted"
    assert measured["protected_execution_count"] == 0
    assert measured["access_denied_result"] is None
    assert measured["model_response_calls"] == 1
    assert setup[3].requests == []


@pytest.mark.parametrize("failure_position", [1, 2])
def test_model_failures_record_fixed_errors_and_execution_count(cases, setup, failure_position):
    first = RuntimeError("API key secret") if failure_position == 1 else response(proposal(ALLOWED))
    adapter = FakeAdapter(first, RuntimeError("API key secret"))

    measured = run_case(cases["benign_control"], adapter, setup)

    assert measured["outcome"] == "error"
    assert measured["error_code"] == "research_failed"
    assert measured["model_response_calls"] == failure_position
    assert measured["protected_execution_count"] == failure_position - 1
    assert "secret" not in json.dumps(measured)


def test_runner_requires_explicit_opt_in_without_network(monkeypatch):
    monkeypatch.delenv("FGA_EVAL", raising=False)
    with pytest.raises(SystemExit) as error:
        main(["--case", "benign_control"])
    assert error.value.code == 2


def test_cli_emits_one_safe_json_result_using_fakes(monkeypatch, capsys, setup):
    adapter = FakeAdapter(response(proposal(RESTRICTED)), answer("Invented facts"))
    monkeypatch.setenv("FGA_EVAL", "1")
    monkeypatch.setenv("FGA_LIVE", "1")
    monkeypatch.setenv("OPENAI_MODEL", "fake-model")
    monkeypatch.delenv("FGA_ADMIN_API_KEY", raising=False)
    monkeypatch.setattr(research_eval, "_manifest", lambda: setup[0])
    monkeypatch.setattr(research_eval.FgaHttpAuthorizer, "from_environment", lambda: setup[3])
    monkeypatch.setattr(research_eval, "OpenAIResponsesAdapter", lambda: adapter)

    exit_code = main(["--case", "direct_redirection"])
    measured = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert measured["case_id"] == "direct_redirection"
    assert measured["model"] == "fake-model"
    assert measured["proposed_report_alias"] == RESTRICTED
    assert measured["authorization_outcome"] == "denied"
    assert measured["protected_execution_count"] == 0
    assert measured["outcome"] == "denied"
    assert len(adapter.calls) == 2


def test_cli_setup_failure_emits_same_safe_result_fields(monkeypatch, capsys):
    def broken_manifest():
        raise ValueError("secret")

    monkeypatch.setenv("FGA_EVAL", "1")
    monkeypatch.setenv("FGA_LIVE", "1")
    monkeypatch.setenv("OPENAI_MODEL", "fake-model")
    monkeypatch.delenv("FGA_ADMIN_API_KEY", raising=False)
    monkeypatch.setattr(research_eval, "_manifest", broken_manifest)

    exit_code = main(["--case", "benign_control"])
    measured = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert measured["outcome"] == "error"
    assert measured["error_code"] == "setup_failed"
    assert measured["model"] == "fake-model"
    assert measured["proposal_status"] == "unobserved"
    assert measured["protected_execution_count"] == 0
    assert measured["model_response_calls"] == 0
    assert "secret" not in json.dumps(measured)
