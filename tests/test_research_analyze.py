"""Offline checks for the fixed experiment-record analyzer."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import agentfence.research_analyze as analyzer
from agentfence.gateway import ActorRecord, Gateway, ReportRecord
from agentfence.research import TRUSTED_ACTOR_KEY
from agentfence.research_eval import RecordingAuthorizer, evaluate, load_cases


CASE_ORDER = (
    "benign_control", "direct_redirection", "forged_authority",
    "task_aligned_manipulation", "answer_contamination",
)


def record(version, case, number):
    commit, digest, _ = analyzer.EXPECTED[version]
    item = {
        "schema_version": 1,
        "case_id": case,
        "model": analyzer.MODEL,
        "expected_report_alias": analyzer.LEGITIMATE,
        "proposed_report_alias": analyzer.LEGITIMATE,
        "proposal_status": "valid",
        "model_redirected": False,
        "authorization_outcome": "authorized",
        "authorization_decision_approved": True,
        "authorization_decision_failure": False,
        "protected_execution_count": 1,
        "access_denied_result": False,
        "answer_marker_present": False if case == "answer_contamination" else None,
        "model_response_calls": 2,
        "outcome": "completed",
        "error_code": None,
        "run_id": f"{number:032x}",
        "timestamp_utc": f"2026-10-19T00:00:{number % 60:02d}Z",
        "git_commit_sha": commit,
        "corpus_sha256": digest,
    }
    if version == "v2":
        item["corpus_version"] = "v2"
    return item


@pytest.fixture
def datasets(tmp_path):
    v1 = [record("v1", case, index * 3 + repeat + 1)
          for index, case in enumerate(CASE_ORDER) for repeat in range(3)]
    extra = record("v1", "forged_authority", 59)
    extra["run_id"] = analyzer.EXTRA_V1_RUN_ID
    v1.insert(0, extra)  # File order differs from chronological order.
    v2 = [record("v2", case, 100 + index * 3 + repeat)
          for index, case in enumerate(CASE_ORDER) for repeat in range(3)]
    paths = (tmp_path / "v1.jsonl", tmp_path / "v2.jsonl")

    def write():
        for path, rows in zip(paths, (v1, v2)):
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return paths

    write()
    return v1, v2, paths, write


def test_valid_datasets_report_retrospective_selection_and_extra(datasets):
    _, _, paths, _ = datasets

    v1, v2 = analyzer.analyze(*paths)
    report = analyzer.format_report(v1, v2)

    assert (v1.stored, v1.planned, v1.completed, v1.failed) == (16, 15, 15, 0)
    assert (v2.stored, v2.planned, v2.completed, v2.failed) == (15, 15, 15, 0)
    assert (v1.benign_correct, v1.redirections, v1.marker_matches) == (3, 0, 0)
    assert (v1.approvals, v1.denials, v1.protected_executions) == (15, 0, 15)
    assert (v1.additional, v2.additional) == (1, 0)
    assert v1.extra_alias == analyzer.LEGITIMATE and v1.extra_executions == 1
    assert "retrospective" in report and analyzer.EXTRA_V1_RUN_ID in report
    assert "0/9" in report and "0/3" in report


def test_denied_redirection_is_not_unauthorized_execution(datasets):
    _, v2, paths, write = datasets
    row = next(row for row in v2 if row["case_id"] == "direct_redirection")
    row.update(
        proposed_report_alias="northstar-q2-board-risks",
        model_redirected=True,
        authorization_outcome="denied",
        authorization_decision_approved=False,
        protected_execution_count=0,
        access_denied_result=True,
        outcome="denied",
    )
    write()

    _, result = analyzer.analyze(*paths)

    assert (result.redirections, result.denials, result.approvals) == (1, 1, 14)
    assert (result.completed, result.failed) == (14, 1)
    assert result.protected_executions == 14
    assert result.unauthorized_executions == 0


def test_service_failure_is_counted_separately(datasets):
    _, v2, paths, write = datasets
    row = next(row for row in v2 if row["case_id"] == "benign_control")
    row.update(
        authorization_outcome="service_failure",
        authorization_decision_approved=False,
        authorization_decision_failure=True,
        protected_execution_count=0,
        access_denied_result=True,
        outcome="error",
        error_code="authorization_service_failure",
    )
    write()

    _, result = analyzer.analyze(*paths)

    assert (result.approvals, result.denials, result.service_failures) == (14, 0, 1)
    assert result.failed == 1 and result.protected_executions == 14


def test_authorizer_exception_record_is_accepted_without_a_decision(datasets):
    _, v2, paths, write = datasets
    row_index = next(i for i, row in enumerate(v2) if row["case_id"] == "benign_control")
    metadata = {key: v2[row_index][key] for key in (
        "run_id", "timestamp_utc", "git_commit_sha", "corpus_sha256"
    )}
    case = next(case for case in load_cases(version="v2") if case.id == "benign_control")
    report_id = "synthetic-report"

    class RaisingAuthorizer:
        def authorize(self, request):
            raise RuntimeError("synthetic transport failure")

    class FakeAdapter:
        def __init__(self):
            self.calls = []

        def create(self, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 1:
                return SimpleNamespace(status="completed", output=[SimpleNamespace(
                    type="function_call", status="completed", name="read_report",
                    call_id="call_1", arguments=json.dumps({"report_id": analyzer.LEGITIMATE}),
                )])
            return SimpleNamespace(status="completed", output=[SimpleNamespace(
                type="message", role="assistant", status="completed",
                content=[SimpleNamespace(type="output_text", text="Access denied.")],
            )])

    recorder = RecordingAuthorizer(RaisingAuthorizer())
    gateway = Gateway(
        {TRUSTED_ACTOR_KEY: ActorRecord("trusted-user", "eu-west", 2)},
        {report_id: ReportRecord(report_id, report_id, "eu-west", 1, "synthetic body")},
        recorder,
    )
    adapter = FakeAdapter()
    measured = evaluate(
        case, adapter, gateway, {analyzer.LEGITIMATE: report_id}, recorder,
        model=analyzer.MODEL, corpus_version="v2", metadata=metadata,
    )

    assert measured["authorization_outcome"] == "service_failure"
    assert measured["authorization_decision_approved"] is None
    assert measured["authorization_decision_failure"] is None
    assert measured["protected_execution_count"] == 0
    assert measured["outcome"] == "error"
    assert measured["error_code"] == "authorization_service_failure"
    assert gateway.execution_log == ()
    assert len(adapter.calls) == 2
    assert "synthetic body" not in json.dumps(measured)
    v2[row_index] = measured
    write()

    _, result = analyzer.analyze(*paths)

    assert (result.approvals, result.denials, result.service_failures) == (14, 0, 1)
    assert result.failed == 1 and result.protected_executions == 14
    assert result.unauthorized_executions == 0


@pytest.mark.parametrize(
    ("approved", "failure", "outcome", "executions", "error_code"),
    [
        (False, None, "error", 0, "authorization_service_failure"),
        (None, True, "error", 0, "authorization_service_failure"),
        (True, True, "error", 0, "authorization_service_failure"),
        (False, False, "error", 0, "authorization_service_failure"),
        (None, None, "completed", 0, None),
        (None, None, "error", 1, "authorization_service_failure"),
        (None, None, "error", 0, "research_failed"),
    ],
)
def test_service_failure_rejects_inconsistent_fields(
    datasets, approved, failure, outcome, executions, error_code
):
    _, v2, paths, write = datasets
    row = next(row for row in v2 if row["case_id"] == "benign_control")
    row.update(
        authorization_outcome="service_failure",
        authorization_decision_approved=approved,
        authorization_decision_failure=failure,
        protected_execution_count=executions,
        access_denied_result=True,
        outcome=outcome,
        error_code=error_code,
    )
    write()

    with pytest.raises(analyzer.AnalysisError, match="service_failure"):
        analyzer.analyze(*paths)


@pytest.mark.parametrize(
    ("change", "diagnostic"),
    [
        (lambda rows: rows[0].update(case_id="other"), "case_id"),
        (lambda rows: rows[0].update(model="other-model"), "model"),
        (lambda rows: rows[0].update(git_commit_sha="bad"), "git_commit_sha"),
        (lambda rows: rows[0].update(corpus_sha256="bad"), "corpus_sha256"),
        (lambda rows: rows[0].update(outcome="unknown"), "outcome"),
        (lambda rows: rows[0].update(model_redirected=True), "model_redirected"),
        (lambda rows: rows[0].update(case_id=[]), "case_id"),
        (lambda rows: rows[0].update(proposed_report_alias=[]), "proposed_report_alias"),
        (lambda rows: rows[0].update(secret="do not print"), "fields"),
    ],
)
def test_invalid_record_fails_with_safe_diagnostic(datasets, change, diagnostic):
    _, v2, paths, write = datasets
    change(v2)
    write()

    with pytest.raises(analyzer.AnalysisError, match=diagnostic) as error:
        analyzer.analyze(*paths)

    assert "do not print" not in str(error.value)


def test_rejects_blank_malformed_and_duplicate_json_keys(datasets):
    _, _, paths, _ = datasets
    original = paths[1].read_text(encoding="utf-8")
    for replacement in ("\n" + original, "{\n" + original, '{"run_id":"a","run_id":"b"}\n' + original):
        paths[1].write_text(replacement, encoding="utf-8")
        with pytest.raises(analyzer.AnalysisError, match="v2 line 1"):
            analyzer.analyze(*paths)


def test_rejects_duplicate_run_ids_within_and_across_datasets(datasets):
    v1, v2, paths, write = datasets
    v2[1]["run_id"] = v2[0]["run_id"]
    write()
    with pytest.raises(analyzer.AnalysisError, match="duplicate run_id"):
        analyzer.analyze(*paths)

    v2[1]["run_id"] = v1[1]["run_id"]
    write()
    with pytest.raises(analyzer.AnalysisError, match="duplicate run_id"):
        analyzer.analyze(*paths)


def test_rejects_extra_records_and_wrong_v1_additional_run(datasets):
    v1, v2, paths, write = datasets
    v2.append(record("v2", "benign_control", 200))
    write()
    with pytest.raises(analyzer.AnalysisError, match="expected 15 records"):
        analyzer.analyze(*paths)

    v2.pop()
    v1[0]["run_id"] = f"{999:032x}"
    write()
    with pytest.raises(analyzer.AnalysisError, match="unexpected additional observation"):
        analyzer.analyze(*paths)


def test_missing_dataset_exits_nonzero_without_partial_report(datasets, monkeypatch, capsys, tmp_path):
    _, _, paths, _ = datasets
    monkeypatch.setattr(analyzer, "DEFAULT_V1", paths[0])
    monkeypatch.setattr(analyzer, "DEFAULT_V2", tmp_path / "missing.jsonl")

    assert analyzer.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "v2: dataset file is missing or unreadable" in output.err


def test_main_prints_summary_from_injected_fixture_paths(datasets, monkeypatch, capsys):
    _, _, paths, _ = datasets
    monkeypatch.setattr(analyzer, "DEFAULT_V1", paths[0])
    monkeypatch.setattr(analyzer, "DEFAULT_V2", paths[1])

    assert analyzer.main() == 0
    output = capsys.readouterr()
    assert "Stored records" in output.out
    assert "retrospective" in output.out
    assert output.err == ""


def test_v2_requires_explicit_corpus_version(datasets):
    _, v2, paths, write = datasets
    del v2[0]["corpus_version"]
    write()

    with pytest.raises(analyzer.AnalysisError, match="invalid fields"):
        analyzer.analyze(*paths)


def test_corpus_file_fingerprint_is_checked(datasets, monkeypatch, tmp_path):
    _, _, paths, _ = datasets
    (tmp_path / "experiments").mkdir()
    (tmp_path / "experiments" / "cases.v1.json").write_bytes(b"changed")
    monkeypatch.setattr(analyzer, "ROOT", tmp_path)

    with pytest.raises(analyzer.AnalysisError, match="corpus file does not match"):
        analyzer.analyze(*paths)
