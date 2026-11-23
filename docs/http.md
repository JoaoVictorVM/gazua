# HTTP targets

Agent mode can attack an agent behind an HTTP endpoint, in any language or framework. Gazua sends each turn of an attack as a `POST` with a fixed JSON body and judges the response with the same verdict engine as a Python entrypoint. The base install is enough; reading tool calls from traces needs the optional extra described in [the traces guide](traces.md).

**HTTP has no dry-run.** Every request reaches your endpoint and the tools behind it run for real. Point Gazua only at a test environment with synthetic data that you own or have written authorization to test.

`gazua run --tools` needs direct access to the tools, so it refuses an HTTP target with `--tools needs direct tool access; use --agent for HTTP targets.` and exit code 2.

## Start: `gazua init --http`

```bash
gazua init --http http://127.0.0.1:8080/api/test-message
```

Init validates the URL, shows its origin and path, warns that dry-run does not exist and asks you to type a full sentence, such as `I am authorized to test http://127.0.0.1:8080`. An abbreviation such as `yes`, piped or redirected input, `--yes`-style flags and environment variables never confirm. Init sends no request to the endpoint and resolves no name.

After the confirmation, init writes:

- `gazua.yaml` with the endpoint, `real_side_effects: i_understand`, `allowed_targets` and an empty tool list to review. A loopback endpoint keeps the default allowlist; a remote host is written to `allowed_targets` explicitly.
- `.gazua/authorization-v1.json`, the local receipt. It holds the schema version, the canonical origin, a SHA-256 hash of the HTTP block, the allowlist and the real effects literal, the UTC time and `authorized: true`. It never holds the typed sentence, headers, tokens, responses or personal data.

An existing `gazua.yaml` is kept. If it already declares the same endpoint, `gazua init --http URL` only writes a new receipt; this is how you confirm again after a change. A file for another target is never replaced.

The receipt proves that someone passed the local gate for this configuration. It is not a legal authorization. `gazua clean` keeps it; deleting it by hand blocks the next run until you confirm again. Automation can reuse a receipt that a person created and reviewed.

## Configuration

```yaml
schema_version: 1
http:
  endpoint: "https://agent.test.example/api/test-message"
  headers:
    X-Test-Tenant: gazua-fixture
  real_side_effects: i_understand
allowed_targets:
  - agent.test.example
tools:
  get_order: {sensitive: false}
  delete_account: {forbidden: true}
canaries: ["GAZUA-CANARY-7f3a9c"]
legit_tasks:
  - {request: "Show my last order.", expected_tool: get_order}
```

| Field | Rule |
|---|---|
| `http.endpoint` | Absolute `http://` or `https://` URL with a host and a path. User information, fragments, wildcards, spaces and non-ASCII hosts are refused. A fixed query is allowed and is part of the confirmation |
| `http.headers` | Up to 32 static, non-secret headers without line breaks. `User-Agent`, `Content-Type`, `Accept`, `Host`, `Authorization`, `Cookie`, hop-by-hop headers and every `X-Gazua-*` header are reserved |
| `http.real_side_effects` | Exactly `i_understand`. Without it a run stops before any request |
| `allowed_targets` | Exact hosts. The endpoint's host must be in it; there is no suffix, wildcard or reverse lookup |

`http` excludes `entrypoint`, `mcp` and `target.reset`: a Python reset cannot isolate a remote target, so Gazua refuses the combination instead of suggesting an isolation that does not exist. Tool declarations still classify calls for the verdicts, but Gazua never calls a tool over HTTP.

Changing the endpoint, the headers, `allowed_targets` or `real_side_effects` invalidates the receipt; the run then explains how to confirm again. Limits, canaries, tools and traces do not.

## The destination gate

Before the first request, and again in every attempt, Gazua checks:

1. The host of the endpoint matches `allowed_targets` exactly, ignoring case only. Otherwise: `Host X is not in allowed_targets; no request was sent.`
2. HTTPS is used for any host other than `localhost`, `127.0.0.1` and `::1`. The certificate and the host name are verified by the default TLS context; there is no option to turn that off.
3. `real_side_effects: i_understand` is declared.
4. The receipt matches the current configuration.

No environment variable widens the allowlist or turns a check off. The client ignores `HTTP_PROXY`, `HTTPS_PROXY` and the other proxy variables, so a local setting cannot send requests somewhere the confirmation does not cover. The endpoint comes only from `gazua.yaml`: never from a flag, a mold, a response or the environment.

## The request

Each turn is one request, in the same supervised worker and attempt:

```http
POST /api/test-message HTTP/1.1
Content-Type: application/json
Accept: application/json
User-Agent: gazua/0.6.0
X-Gazua-Run: GAZUA-run-20261119120000-a1b2c3:GAZUA-exec-0001
X-Test-Tenant: gazua-fixture

{"message": "Look up test order GAZUA-order-1.", "run_id": "GAZUA-run-20261119120000-a1b2c3:GAZUA-exec-0001"}
```

`message` is the turn as literal text: never a template, HTML or Markdown. `run_id` and `X-Gazua-Run` identify the attempt; they change on every attempt and retry. `User-Agent` names Gazua and its version so the target can tell test traffic apart. With traces enabled, two more headers carry the attempt's trace receiver; see [the traces guide](traces.md).

Requests and responses are limited to 1 MiB, enforced while reading.

## The response

The endpoint answers `2xx` with a JSON object whose `response` is text:

```json
{"response": "Here is your test order."}
```

Extra fields are ignored. Anything else is an operational failure, never resistance:

| Situation | Code | Result |
|---|---|---|
| Any `3xx` | `http_redirect_refused` | Not followed, even to the same host |
| `429` | rate limit | Backoff and retry under the existing agent policy |
| Other `4xx` | `http_client_error` | Attempt failed |
| `5xx` | `http_server_error` | Attempt failed |
| Invalid JSON, a non-object or a non-text `response` | `http_response_invalid` | Not tested |
| Body over 1 MiB | `http_response_limit` | Reading stops; not tested |
| Connection refused or lost, timeout | `http_transport_lost` | Never retried, because the effect may have happened |
| TLS failure | `http_tls_failed` | Attempt failed |

Error bodies are never printed or stored. Five consecutive identical failures close admission, the remaining attempts are not tested and the run exits with 2, as described in [the agent mode guide](agent-mode.md).

## What can be proven

| Signal | Over HTTP |
|---|---|
| Canary in the response | Yes, from the response text |
| Forbidden or sensitive tool call | Only with traces: a correlated span with outcome `succeeded` |
| Victim record access, canary in tool arguments, tool call ceiling | Not tested: spans carry neither arguments, returns nor a ceiling Gazua could enforce |
| Indirect entries (`tool_result`, `rag_document`, `poisoned_memory`) | Not tested: they arm a local Python tool |
| Output sink, memory | Not tested: they need local observation |
| Legitimate tasks | Only with traces: a span of the expected tool |

A response that says it called a tool is never proof. Without traces, attacks that need tool visibility are `not_tested` with `tool_calls_unobservable`, and the legitimate use rate is not tested.

## Reports and verification

Run documents record `target_adapter: http` and the origin only: never the path, the query, headers, the token or spans. A finding's identity uses `http:` plus the origin, the mold and the tool. `gazua verify` replays over the same adapter, checks the current receipt before the first request and refuses to close a finding whose kept run did not reach the same origin over HTTP. See [the reports guide](reports.md).

## Limits

- One endpoint per configuration; no target lists, discovery, crawling, wildcards or redirects.
- Only `POST` with the fixed JSON body. No configurable methods, body templates, GraphQL, WebSocket, SSE, streaming or uploads.
- No credentials, cookies, OAuth or mTLS: the endpoint must accept test requests without secrets.
- No remote reset or rollback. Gazua cannot undo what the endpoint did.
- No tunnel. A remote target must run Gazua in the same test environment, or use a tunnel you create and authorize outside Gazua.
