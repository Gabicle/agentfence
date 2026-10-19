"""Offline checks for the separate administrative fixture script."""

import base64
import json

import pytest

from scripts import setup_fga_live


DB_NAME = "agentfence_live_disposable_abcdef123456"
ADMIN_KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def test_setup_creates_only_three_grants_and_non_secret_manifest(
    monkeypatch, tmp_path, capsys
) -> None:
    grants = []
    monkeypatch.setattr(setup_fga_live, "ROOT", tmp_path)
    monkeypatch.setattr(
        setup_fga_live,
        "_grant",
        lambda opener, origin, key, subject, report: grants.append((origin, key, subject, report)),
    )
    monkeypatch.setenv("FGA_LIVE", "1")
    monkeypatch.setenv("FGA_LIVE_DB_NAME", DB_NAME)
    monkeypatch.setenv(
        "ConnectionStrings__DefaultConnection",
        f"Host=127.0.0.1;Database={DB_NAME};Username=postgres;Password=synthetic-password",
    )
    monkeypatch.setenv("FGA_AUTHORIZATION_URL", "http://127.0.0.1:5031")
    monkeypatch.setenv("FGA_ADMIN_API_KEY", ADMIN_KEY)

    setup_fga_live.main()

    manifests = list((tmp_path / ".fga-live").glob("fixture-*.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    reports = manifest["reports"]
    assert manifest["actor"]["region"] == "eu-west"
    assert manifest["actor"]["clearance_level"] == 2
    assert len(grants) == 3
    assert {grant[3] for grant in grants} == {
        reports[name]["id"] for name in ("allowed", "region_denied", "sensitivity_denied")
    }
    assert reports["ungranted"]["id"] not in {grant[3] for grant in grants}
    assert {grant[2] for grant in grants} == {manifest["actor"]["id"]}
    assert all(grant[1] == ADMIN_KEY for grant in grants)
    assert ADMIN_KEY not in manifests[0].read_text(encoding="utf-8")
    assert "synthetic-password" not in manifests[0].read_text(encoding="utf-8")
    assert ADMIN_KEY not in capsys.readouterr().out


def test_setup_rejects_existing_integration_database_before_grants(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(setup_fga_live, "ROOT", tmp_path)
    monkeypatch.setenv("FGA_LIVE", "1")
    monkeypatch.setenv("FGA_LIVE_DB_NAME", "permissions_integration_disposable")
    monkeypatch.setattr(setup_fga_live, "_grant", lambda *args: pytest.fail("unexpected grant"))

    with pytest.raises(RuntimeError, match="fresh agentfence_live_disposable"):
        setup_fga_live.main()

    assert not (tmp_path / ".fga-live").exists()
