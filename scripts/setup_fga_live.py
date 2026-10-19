"""Create unique report/viewer fixtures using the admin key in this process only."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid


ROOT = Path(__file__).resolve().parents[1]
DISPOSABLE_DB = re.compile(r"agentfence_live_disposable_[0-9a-f]{12}\Z")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _database_name(connection_string: str) -> str | None:
    names = [
        value.strip()
        for part in connection_string.split(";")
        if "=" in part
        for key, value in [part.split("=", 1)]
        if key.strip().lower() == "database"
    ]
    return names[0] if len(names) == 1 else None


def _service_origin(value: str | None) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        raise RuntimeError("FGA_AUTHORIZATION_URL must be a valid service origin.") from None
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
        raise RuntimeError("FGA_AUTHORIZATION_URL must be a valid service origin.")
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise RuntimeError("Fixture setup requires a loopback authorization service.")
    return value.rstrip("/")


def _admin_key(value: str | None) -> str:
    if not value:
        raise RuntimeError("FGA_ADMIN_API_KEY is required for fixture setup.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise RuntimeError("FGA_ADMIN_API_KEY must encode 32 bytes.") from None
    if len(decoded) != 32 or len(set(decoded)) == 1:
        raise RuntimeError("FGA_ADMIN_API_KEY must encode a non-degenerate 32-byte key.")
    return value


def _grant(opener, origin: str, admin_key: str, subject_id: str, report_id: str) -> None:
    body = {
        "subjectType": "user",
        "subjectId": subject_id,
        "relation": "viewer",
        "objectType": "report",
        "objectId": report_id,
    }
    request = urllib.request.Request(
        origin + "/api/permissions/grant",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": "ApiKey " + admin_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with opener.open(request, timeout=5) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    except urllib.error.URLError:
        raise RuntimeError("Fixture grant failed: authorization service is unreachable.") from None
    if status != 204:
        raise RuntimeError(f"Fixture grant failed with HTTP {status}; no manifest was written.")


def main() -> None:
    if os.environ.get("FGA_LIVE") != "1":
        raise RuntimeError("Set FGA_LIVE=1 to opt in to fixture setup.")
    database_name = os.environ.get("FGA_LIVE_DB_NAME", "")
    if DISPOSABLE_DB.fullmatch(database_name) is None:
        raise RuntimeError("FGA_LIVE_DB_NAME must identify a fresh agentfence_live_disposable_<12 hex> database.")
    connection_string = os.environ.get("ConnectionStrings__DefaultConnection", "")
    if _database_name(connection_string) != database_name:
        raise RuntimeError("ConnectionStrings__DefaultConnection must name the same disposable database.")
    origin = _service_origin(os.environ.get("FGA_AUTHORIZATION_URL"))
    admin_key = _admin_key(os.environ.get("FGA_ADMIN_API_KEY"))

    suffix = uuid.uuid4().hex
    subject_id = "agentfence-live-user-" + suffix
    reports = {
        "allowed": {"id": "agentfence-live-report-allowed-" + suffix, "region": "eu-west", "sensitivity_level": 1},
        "region_denied": {"id": "agentfence-live-report-region-" + suffix, "region": "us-east", "sensitivity_level": 1},
        "sensitivity_denied": {"id": "agentfence-live-report-sensitivity-" + suffix, "region": "eu-west", "sensitivity_level": 3},
        "ungranted": {"id": "agentfence-live-report-ungranted-" + suffix, "region": "eu-west", "sensitivity_level": 1},
    }
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    for name in ("allowed", "region_denied", "sensitivity_denied"):
        _grant(opener, origin, admin_key, subject_id, reports[name]["id"])

    manifest = {
        "schema_version": 1,
        "actor": {"id": subject_id, "region": "eu-west", "clearance_level": 2},
        "reports": reports,
    }
    directory = ROOT / ".fga-live"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / f"fixture-{suffix}.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)
        file.write("\n")
    print(f"Created three synthetic grants. Set FGA_LIVE_MANIFEST={path}")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
