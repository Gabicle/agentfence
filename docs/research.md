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

Each question permits one report proposal and at most two Responses API calls.
The calls use `store=False`, a 20-second SDK timeout, and no automatic SDK
retries. The final call offers no tools. Run the offline suite without any
OpenAI or fga-dotnet credentials:

```bash
python3 -m pytest -q
```
