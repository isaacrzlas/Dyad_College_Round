# AgentBreak

AgentBreak is a local, synthetic AI-agent red-team workbench. It demonstrates how user prompts and untrusted retrieved content can lead a deliberately vulnerable support agent to perform an unauthorized mock action, records the evidence, reconstructs saved traces, re-executes saved inputs against a selected target, and checks legitimate workflows.

All records, identities, documents, and tools are synthetic. The execution boundary is a controlled application-level simulation; it is not operating-system isolation. No real email, customer record, external target, or shell command is used.

## Start the app

Requirements: Python 3.10+ and Node.js 20+.

```powershell
python -m pip install -r backend/requirements.txt
python -m uvicorn app:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open <http://127.0.0.1:5173>. Select **Run Guided Demo** for the credential-free end-to-end synthetic exploit, hardened replay, benign regressions, and saved comparison. SQLite is created at `backend/agentbreak.sqlite3`; set `AGENTBREAK_DB` to choose another path.

## Implemented capabilities

- Seeded vulnerable and hardened simulator targets with explicit tools, role boundaries, permissions, scopes, approval flags, and policy settings.
- Configurable target manifests with create, edit, duplicate, delete, version history, schema validation, and configuration audit findings.
- A reference integration for explicitly instrumented targets, with target identification/version, declared tool schemas, session lifecycle, health checks, input delivery, response capture, intermediate decisions, tool proposals/outcomes, and declared/observed/inaccessible state labels. The local reference agent is seeded as `reference-vulnerable` and `reference-hardened`.
- Bounded campaign generation with reproducible seeds, persisted candidate nodes, parent/depth/rationale, trace-feedback follow-ups, outcomes, and linked evidence traces. Candidate sources are labeled as predefined scenarios, deterministic mutations, feedback-driven discoveries, or model-generated candidates. Deterministic follow-ups are selected from observed policy decisions and tool or memory events, deduplicated by normalized category and prompt, and scheduled by evidence priority within the campaign's bounded adaptive budget.
- A real simulator policy gate checks whether tools are enabled and validates identity, declared permission, resource scope, and approval before synthetic actions. Regression runs use the same gate; the intentionally vulnerable profile bypasses it to produce controlled findings.
- Optional OpenAI-compatible model-assisted candidate generation and adaptive follow-ups. Fresh live reproductions run the configured harness against synthetic prompts, documents, and registered simulator tools; every proposed call passes through the local authorization dispatcher and is saved with a security outcome and trace.
- Multi-stage simulated attack traces with attacker input, retrieval trust labels, agent decisions, proposed tools, policy outcomes, mock tool result, and final evidence.
- Session- and target-scoped SQLite memory with trust labels, provenance, version history, snapshots, restore, and reset. Memory poisoning is persisted as untrusted state on the vulnerable target and rejected on the hardened target.
- Recorded event reconstruction returns the exact persisted source trace references and never invokes a target or repeats side effects. Fresh target re-execution runs saved input through the selected simulator or local instrumented reference and stores new event IDs linked to the original source trace. Fresh model reruns are a separate mode.
- Defense validation that freezes the completed baseline candidate corpus and replays the same prompts against hardened policy. Metrics expose executed and inconclusive counts and their denominators.
- Twenty-five regression task definitions with explicit initial state, operation, expected outcome, permitted/prohibited side effects, and named behavioral assertions. Each run executes both the vulnerable baseline and hardened target through the same simulator and authorization dispatcher.
- Regression outcomes use `passed`, `failed`, `skipped`, `errored`, or `inconclusive`; saved results include validation ID, target configuration version, explanation, and trace references. Errors and missing evidence are never counted as successful defenses.
- Dashboard, finding and trace explorers, adaptive discovery tree, target editor/auditor, memory inspector, replay lab, defense comparison, and regression view.
- Static permission audit findings include severity, affected tool, problematic configuration, concrete remediation, a suggested manifest change when intended scope is known, and uncertainty notes. Validation exports include both targets' static configuration audit results.
- A reproducible held-out trace-pattern evaluation reports which feedback strategies were selected. It is a candidate-strategy check, not evidence that a vulnerability was discovered or exploited.
- JSON campaign export and additive SQLite schema migration marker.
- Complete persisted JSON exports for paired defense validations and replay runs, including source candidates, case outcomes, regression evidence, and trace events.

## Current adapter boundary

The app executes built-in simulator targets and the explicitly instrumented **local reference agent**. The reference target exposes a small decision flow and only registered synthetic tools; its proposals pass through AgentBreak's shared authorization dispatcher. Its declared tool inventory comes from the adapter contract, while decisions, proposals, and outcomes are observed during a run. Model weights, private runtime state, and undeclared tools remain inaccessible. For a target whose tools execute internally without interception, AgentBreak cannot guarantee enforcement.

Set `LLM_BASE_URL`, `LLM_MODEL`, and optionally `LLM_API_KEY` in the backend environment to enable model-assisted candidate generation and fresh model reruns. A connected generic chat model acts as a simulated target under configured system instructions; it does not connect to or reveal an unrelated deployed agent. It receives synthetic prompts and retrieved documents as untrusted context, can propose only registered simulator tools, and every proposal is dispatched through local authorization. No arbitrary code, real customer access, or external actions are available. Requests have 15-second timeouts, 256KB request and 1MB response limits, a 60-request/minute process limit, 20 live cases per run, at most three model turns per case, and four tool proposals per turn. Model manifests can be stored and audited but are not executed. Settings never returns provider credentials.

## Target manifest

The editable built-in targets show the schema in the UI. A sample is at `backend/examples/hardened-target.json`. Version 1 manifests have a `schema_version`, adapter label, target mode, identity, tool declarations (`name`, `enabled`, `risk`, `roles`, permissions, scope, and optional schema), and policy flags. The audit flags high-risk tools without approval, unrestricted scopes, absent role boundaries, missing allowlist enforcement, and unsafe memory authorization policy.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | API and simulation status |
| GET | `/api/dashboard/summary` | Dashboard metrics |
| GET/POST/PUT/DELETE | `/api/targets` and `/api/targets/{id}` | Target manifest CRUD |
| POST / GET | `/api/targets/{id}/audit` | Run/read manifest permission audit |
| GET | `/api/targets/{id}/capabilities` | Inspect declared adapter capabilities and visibility limits |
| POST | `/api/targets/{id}/duplicate` | Clone a target as an editable version 1 |
| POST | `/api/campaigns/run` | Run bounded campaign (`target`, `target_id`, `categories`, `max_tests`, `seed`, `session_id`) |
| GET | `/api/campaigns/{id}/tree` | Persisted candidate tree |
| GET | `/api/campaigns/{id}` | Campaign, traces, and findings |
| POST | `/api/replay/run` | `recorded` event reconstruction, `reexecute` fresh target run, or `live` fresh model rerun |
| POST | `/api/discovery/held-out/evaluate` | Evaluate feedback-strategy selection on four held-out trace patterns |
| GET | `/api/replays`, `/api/replays/{id}` | Replay run and per-case results |
| GET | `/api/replays/{id}/export` | Download persisted replay evidence and traces |
| POST | `/api/defense/validate` | Frozen attack replay plus comparative behavioral regression runs |
| GET/POST/PATCH/DELETE | `/api/regressions` and `/api/regressions/{id}` | Regression case definitions |
| POST | `/api/regression/run` | Run regressions against baseline and hardened targets; pass `target_id` to execute one target |
| GET | `/api/regression/runs/{id}` | Retrieve persisted task results, assertions, outcomes, and trace references |
| GET/POST/DELETE | `/api/memory` | Read, write untrusted memory, or reset a session |
| POST / GET | `/api/memory/snapshot`, `/api/memory/snapshots` | Create/list session snapshots |
| POST | `/api/memory/snapshots/{id}/restore` | Restore a saved snapshot |
| GET | `/api/memory/history` | Inspect version history |
| GET | `/api/findings`, `/api/findings/{id}` | Search findings and linked evidence |
| GET | `/api/traces/{id}` | Ordered trace events |
| GET | `/api/validations/latest` | Most recent validation |
| GET | `/api/validations/{id}/export` | Download complete paired validation evidence |
| GET | `/api/campaigns/{id}/export` | Download campaign evidence JSON |

API docs: <http://127.0.0.1:8000/docs>.

## Tests and build

```powershell
python -m pytest backend/tests -q --basetemp backend/.pytest-tmp
cd frontend
npm run build
```

The tests cover target seeding and audits, policy enforcement, scope-aware regressions, optional model candidate wiring, behavioral assertions across 25 regression tasks, persisted history and trace links, adaptive tree persistence, untrusted memory versioning and restore, recorded replay, complete evidence exports, secret redaction, backend restart persistence, and baseline/hardened corpus comparability. The OpenAI-compatible adapter is tested against a local mocked endpoint, including bounded tool proposals and timeouts; no paid provider is needed for the test suite.

## Limits

AgentBreak's local instrumented reference proves the adapter contract but does not connect to arbitrary deployed agents. It does not run arbitrary target tools, provide OS/container isolation, certify a real system, or send actions to third-party services. The optional OpenAI-compatible harness has been tested against a local mock endpoint; a real external provider must be configured server-side and was not tested as part of this acceptance run. The held-out evaluation scores expected strategy selection on four synthetic trace fixtures; it does not establish improved exploit discovery.
