# AF-002b live permission proof

The opt-in suite checks AgentFence against the
[`fga-integration-v1.1` fga-dotnet baseline](https://github.com/Gabicle/fga-dotnet/tree/fga-integration-v1.1).
It uses a separate Docker Compose project named `agentfence-live`, with a
disposable PostgreSQL 16 volume and an API published at
`http://127.0.0.1:8081`. Run these commands from the AgentFence repository root.
Keep the ordinary fga-dotnet checkout, Compose project, database, and port 8080
untouched.

## Create the disposable service

Docker with Compose version 2.24.4 or later (required for `!override`),
OpenSSL, and Python with pytest are required. The build also needs access to
pull its Docker images and restore NuGet packages.
Use a separate checkout of the baseline beside AgentFence; do not switch the
ordinary fga-dotnet checkout:

```bash
git clone --branch fga-integration-v1.1 --depth 1 \
  https://github.com/Gabicle/fga-dotnet.git ../fga-dotnet-agentfence-live
```

In a private shell, create a fresh, Git-ignored `.fga-live/` directory. Keep
these files private and do not overwrite a previous run's files while its
Compose project is active. The override gives this project its own image tag
and loopback port; the base Compose file supplies the database, migrator, and
API services.

```bash
umask 077
mkdir -p .fga-live
unset POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD
unset PERMISSIONS_CHECK_API_KEY PERMISSIONS_ADMIN_API_KEY
db_name="agentfence_live_disposable_$(openssl rand -hex 6)"
db_password="$(openssl rand -hex 32)"
check_key="$(openssl rand -base64 32)"
admin_key="$(openssl rand -base64 32)"
cat > .fga-live/compose.env <<EOF
POSTGRES_DB=$db_name
POSTGRES_USER=postgres
POSTGRES_PASSWORD=$db_password
PERMISSIONS_CHECK_API_KEY=$check_key
PERMISSIONS_ADMIN_API_KEY=$admin_key
EOF
cat > .fga-live/compose.override.yaml <<'EOF'
services:
  migrate:
    image: fga-dotnet:agentfence-live
  api:
    image: fga-dotnet:agentfence-live
    ports: !override
      - "127.0.0.1:8081:8080"
EOF
unset db_name db_password check_key admin_key
docker compose -p agentfence-live --env-file .fga-live/compose.env \
  -f ../fga-dotnet-agentfence-live/compose.yaml \
  -f .fga-live/compose.override.yaml up -d --build
docker compose -p agentfence-live --env-file .fga-live/compose.env \
  -f ../fga-dotnet-agentfence-live/compose.yaml \
  -f .fga-live/compose.override.yaml ps
```

Compose waits for the database, runs the one-shot migrator, then starts the API.
The database has no published host port. The check and admin keys are distinct;
the container receives both, while each Python process below receives only the
key it needs. Keep the environment file out of Git and away from shared logs.

## Provision fixtures with the admin key

In a separate setup shell, pass the admin key and the same disposable database
name and connection string used by Compose. The script makes three synthetic
`report/viewer` grants and writes a private manifest under `.fga-live/`. It
does not create or delete a database, and its database check cannot verify an
already-running service's connection, so confirm the isolated Compose project
before provisioning.

```bash
unset FGA_CHECK_API_KEY
db_name="$(sed -n 's/^POSTGRES_DB=//p' .fga-live/compose.env)"
db_password="$(sed -n 's/^POSTGRES_PASSWORD=//p' .fga-live/compose.env)"
admin_key="$(sed -n 's/^PERMISSIONS_ADMIN_API_KEY=//p' .fga-live/compose.env)"
FGA_LIVE=1 FGA_AUTHORIZATION_URL=http://127.0.0.1:8081 \
  FGA_LIVE_DB_NAME="$db_name" \
  ConnectionStrings__DefaultConnection="Host=db;Port=5432;Database=$db_name;Username=postgres;Password=$db_password;GSS Encryption Mode=Disable" \
  FGA_ADMIN_API_KEY="$admin_key" \
  python3 scripts/setup_fga_live.py
unset db_name db_password admin_key
```

Save the printed `.fga-live/fixture-<run-id>.json` path for the test process.
It contains synthetic identifiers and attributes, not API keys.

## Run the six live tests

In a fresh, check-only shell, set the manifest path printed above. Do not pass
the admin key to pytest. Five tests contact the real authorization service:
four check granted and denied reports through the gateway, and one sends a
deterministic fake OpenAI proposal for the restricted board-risks report
through ResearchAgent and the gateway. That test verifies an explicit
`required_abac_denied` decision and zero protected executions. The sixth test
checks fail-closed behavior against an unavailable endpoint.

```bash
unset FGA_ADMIN_API_KEY FGA_SHOW_DECISIONS
manifest=".fga-live/fixture-<run-id>.json"  # replace with the printed path
check_key="$(sed -n 's/^PERMISSIONS_CHECK_API_KEY=//p' .fga-live/compose.env)"
FGA_LIVE=1 FGA_AUTHORIZATION_URL=http://127.0.0.1:8081 \
  FGA_CHECK_API_KEY="$check_key" FGA_LIVE_MANIFEST="$manifest" \
  python3 -m pytest -q -m live
unset check_key
```

For decision correlation, add `FGA_SHOW_DECISIONS=1` to the test command and
pass `-s` to pytest:

```bash
unset FGA_ADMIN_API_KEY
manifest=".fga-live/fixture-<run-id>.json"  # replace with the printed path
check_key="$(sed -n 's/^PERMISSIONS_CHECK_API_KEY=//p' .fga-live/compose.env)"
FGA_LIVE=1 FGA_AUTHORIZATION_URL=http://127.0.0.1:8081 \
  FGA_CHECK_API_KEY="$check_key" FGA_LIVE_MANIFEST="$manifest" \
  FGA_SHOW_DECISIONS=1 python3 -m pytest -q -m live -s
unset check_key
```

This prints `decision_id`, `approved`, and `reason_code` for each of the five
real authorization responses. Match each Python `decision_id` to the
`DecisionId` in the API's structured `AuthorizationDecision` event ID `1001`.
The ID originates in the `X-Authorization-Decision-Id` response header. Inspect
only this project's API logs and search for that ID:

```bash
docker compose -p agentfence-live --env-file .fga-live/compose.env \
  -f ../fga-dotnet-agentfence-live/compose.yaml \
  -f .fga-live/compose.override.yaml logs api
```

Decision logs include checked identifiers, so restrict their access. The
unavailable-endpoint test has no service decision ID to correlate.

Without `FGA_LIVE=1`, the live tests skip during a normal `python3 -m pytest -q`
run. With live mode enabled, missing configuration or service failures fail the
suite.

## Clean up this project only

After the run, remove only the `agentfence-live` containers, network, and
disposable `agentfence-live_postgres_data` volume:

```bash
docker compose -p agentfence-live --env-file .fga-live/compose.env \
  -f ../fga-dotnet-agentfence-live/compose.yaml \
  -f .fga-live/compose.override.yaml down --volumes
```

Keep the `-p agentfence-live` flag and both file paths in the cleanup command.
Do not run `down --volumes` against the ordinary fga-dotnet project or use a
global Docker prune. Once cleanup succeeds, the private `.fga-live/` files and
separate checkout can be removed if no longer needed.
