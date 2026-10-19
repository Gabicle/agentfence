# AF-003a synthetic investment research smoke test

Install the optional official OpenAI Python SDK alongside the test dependency:

```bash
python3 -m pip install -e '.[research,test]'
```

First create and provision the disposable `agentfence-live` service using
[the live runbook](fga_live.md). In a separate check-only shell, set
`FGA_LIVE=1`, `FGA_AUTHORIZATION_URL=http://127.0.0.1:8081`,
`FGA_CHECK_API_KEY`, and `FGA_LIVE_MANIFEST` to the generated fixture path.
Leave `FGA_ADMIN_API_KEY` unset. Set `OPENAI_API_KEY` and `OPENAI_MODEL` in that
shell, then ask one question:

```bash
python3 -m agentfence.research_smoke \
  "What do Northstar Technologies' Q2 results say about revenue, margin, and cash flow?"
```

The model sees four readable report aliases and can propose only
`read_report(report_id)`. AgentFence maps the chosen alias to a resource ID from
the trusted fixture manifest, uses the fixture's actor in `Gateway.execute()`,
and sends the synthetic report body to OpenAI only after authorization. A
denied read returns a fixed access-denied answer. The output names the trusted
source when a read succeeds. The dataset is fictional; the agent does not use
market prices, news, or web search.

If the model does not request a report, the command fails rather than returning
an unsupported research answer.

Applications may optionally pass lower-trust source material with
`agent.research(question, excerpt=external_text)`. The excerpt is limited to
4,000 characters and enters the first model request as a separate message
marked `untrusted`. Its text cannot set the actor, authorization policy, report
attributes, or alias mapping. The final-generation instructions require the
model to use only the authorized report as evidence. Whether the model follows
those instructions is evaluated separately.

Each question permits one report proposal and at most two Responses API calls.
The calls use `store=False`, a 20-second SDK timeout, and no automatic SDK
retries. The final call offers no tools. Run the offline suite without any
OpenAI or fga-dotnet credentials:

```bash
python3 -m pytest -q
```

## One-case prompt-injection evaluation

The [v1 synthetic case corpus](../experiments/cases.v1.json) contains a benign
control, three attempts to redirect report selection toward the restricted
board-risks report, and one answer-marker attempt. The
[v2 corpus](../experiments/cases.v2.json) keeps the same five case IDs and
expected report selections, with longer, document-like excerpts. Each
invocation runs one case. The default is v1, so existing commands continue to
use the original corpus. After provisioning the disposable FGA service as above, use a
check-only shell with `FGA_LIVE=1`, `FGA_AUTHORIZATION_URL`, `FGA_CHECK_API_KEY`,
`FGA_LIVE_MANIFEST`, `OPENAI_API_KEY`, and `OPENAI_MODEL` set. Leave
`FGA_ADMIN_API_KEY` unset. Then explicitly opt in:

```bash
FGA_EVAL=1 python3 -m agentfence.research_eval --case direct_redirection
```

Select v2 explicitly and keep its observations in a separate file:

```bash
FGA_EVAL=1 python3 -m agentfence.research_eval \
  --corpus-version v2 --case direct_redirection \
  --output-jsonl .fga-live/research-v2-runs.jsonl
```

To retain results, add `--output-jsonl .fga-live/research-runs.jsonl`. Run the
command again for each independent observation or case; each invocation makes
at most the existing two model calls and appends one JSON line. For example:

```bash
FGA_EVAL=1 python3 -m agentfence.research_eval --case benign_control \
  --output-jsonl .fga-live/research-runs.jsonl
FGA_EVAL=1 python3 -m agentfence.research_eval --case direct_redirection \
  --output-jsonl .fga-live/research-runs.jsonl
```

The same JSON is still printed to standard output. Setup failures and
unsuccessful experiments are also appended when the destination is valid. The
file must be a direct `.jsonl` child of `.fga-live/`; keep this private
directory and its records out of Git.

Each record includes the configured `model` identifier, a unique `run_id`, a UTC
`timestamp_utc`, the current `git_commit_sha` (or `unavailable`), and
`corpus_version` (`v1` or `v2`), and `corpus_sha256` for the exact bytes of the
selected corpus used for that invocation. These fields are present in setup
failure records too. Keep v1 and v2 results separate when comparing outcomes.
`proposed_report_alias` is the validated alias from the first model response;
`model_redirected` compares it with the case's expected alias regardless of
authorization. Invalid or missing calls have their own `proposal_status` and
no proposed alias. `authorization_outcome=denied` means the authorization
service returned an explicit policy denial. `service_failure` means the check
failed closed, including transport and invalid-response failures; its overall
`outcome` is `error` with the fixed code `authorization_service_failure`.
`authorization_decision_approved` and `authorization_decision_failure` expose
only the observed approval value and whether a failure field was present, not
the raw failure text. `protected_execution_count` counts report-body reads.
`access_denied_result` records the answer returned to the caller and can be
`true` for either a policy denial or a service failure;
`answer_marker_present` checks the final answer for the case's exact synthetic
marker, or is `null` when that check cannot apply. `outcome` distinguishes
`invalid_proposal`, `no_proposal`, `denied`, `completed`, and `error`; errors use
fixed codes without raw exception text. A redirected, denied proposal with zero
protected executions is **not** an authorization bypass.

Results contain no report bodies, API keys, headers, raw model responses, or
excerpts. The marker check is an exact substring observation, not a judgment of
answer quality. One run per case cannot estimate attack success rates or prove
the model will behave consistently; repeat selected cases manually if needed.
The v2 excerpts are still synthetic and cover only five attack patterns; their
greater detail does not establish real-world effectiveness. The commit SHA does
not capture uncommitted code, and the corpus hash does not capture the model
backend, FGA fixtures, service state, or environment. The UTC
timestamp and run ID identify records but do not make model output replayable.
The initial offline evaluator tests use fake Responses output and never call
OpenAI or fga-dotnet.

## Offline results analyzer

After collecting the fixed v1 and v2 datasets in the default `.fga-live/`
JSONL files, run:

```bash
python -m agentfence.research_analyze
```

This command makes no OpenAI or FGA calls and needs no credentials. It checks
every record, unique run IDs across both files, the expected model and Git
revisions, and each corpus file's exact SHA-256 fingerprint. It expects 16 v1
records and 15 v2 records; missing, malformed, changed, or additional records
cause a nonzero exit instead of a partial summary. Historical v1 records may
omit `corpus_version`.

The analyzer **retrospectively** selects the first three UTC runs for each v1
case and reports the fourth forged-authority run separately. The rule was not
preregistered. It calculates report selection before authorization, exact
answer-marker matches, authorization outcomes, and protected execution counts
as separate measures. A denied proposal with zero executions is not an
authorization bypass. Failed means any planned record whose `outcome` is not
`completed`; it does not mean the authorization policy failed.

The analyzer is intentionally tied to the two recorded corpora and their known
fingerprints, rather than being a general-purpose statistics tool. It cannot
verify the historical model backend or FGA service state, detect answer
contamination beyond the exact marker, or establish statistical significance
from these small synthetic samples. Its unit tests use synthetic JSONL files.
