# AgentBreak

AgentBreak is a local, synthetic AI-agent red-team workbench. It demonstrates how user prompts and untrusted retrieved content can lead a deliberately vulnerable support agent to perform an unauthorized mock action, records the evidence, replays the same attack inputs against hardened policy, and checks that legitimate workflows still pass.

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

Open <http://127.0.0.1:5173>. Select **Run Live Demo** for the end-to-end synthetic exploit, hardened replay, benign regressions, and saved comparison. SQLite is created at `backend/agentbreak.sqlite3`; set `AGENTBREAK_DB` to choose another path.

## Implemented capabilities

- Seeded vulnerable and hardened simulator targets with explicit tools, role boundaries, permissions, scopes, approval flags, and policy settings.
- Configurable target manifests with create, edit, duplicate, delete, version history, schema validation, and configuration audit findings.
- Bounded campaign generation with reproducible seeds, persisted candidate nodes, parent/depth/rationale, signal-guided follow-ups, outcomes, and linked evidence traces.
- A real simulator policy gate checks whether tools are enabled and validates identity, declared permission, resource scope, and approval before synthetic actions. Regression runs use the same gate; the intentionally vulnerable profile bypasses it to produce controlled findings.
- Optional OpenAI-compatible model-assisted candidate generation and adaptive follow-ups, with prompts and outcomes retained in traces. The model proposes tests only; it cannot execute target tools.
- Multi-stage simulated attack traces with attacker input, retrieval trust labels, agent decisions, proposed tools, policy outcomes, mock tool result, and final evidence.
- Session- and target-scoped SQLite memory with trust labels, provenance, version history, snapshots, restore, and reset. Memory poisoning is persisted as untrusted state on the vulnerable target and rejected on the hardened target.
- Frozen-corpus recorded replay that repeats completed baseline prompts against a selected simulator target; each replay and case result is persisted separately.
- Defense validation that freezes the completed baseline candidate corpus and replays the same prompts against hardened policy. Metrics expose executed and inconclusive counts and their denominators.
- Twenty-five regression task definitions with explicit initial state, operation, expected outcome, permitted/prohibited side effects, and named behavioral assertions. Each run executes both the vulnerable baseline and hardened target through the same simulator and authorization dispatcher.
- Regression outcomes use `passed`, `failed`, `skipped`, `errored`, or `inconclusive`; saved results include validation ID, target configuration version, explanation, and trace references. Errors and missing evidence are never counted as successful defenses.
- Dashboard, finding and trace explorers, adaptive discovery tree, target editor/auditor, memory inspector, replay lab, defense comparison, and regression view.
- JSON campaign export and additive SQLite schema migration marker.

## Current adapter boundary

This checkout executes **simulator** targets only. Set `LLM_BASE_URL`, `LLM_MODEL`, and optionally `LLM_API_KEY` to enable model-assisted adversarial candidate generation; these calls generate test prompts only. Target manifests with `model_harness` or `manifest` adapter labels can be stored and audited, but target-agent calls and live reproduction are not wired in. The Replay Lab uses recorded deterministic replay. Do not interpret a manifest audit as a test of a deployed agent. Settings never returns environment secrets.

## Target manifest

The editable built-in targets show the schema in the UI. A sample is at `backend/examples/hardened-target.json`. Version 1 manifests have a `schema_version`, adapter label, simulator mode, identity, tool declarations (`name`, `enabled`, `risk`, `roles`, permissions, and scope), and policy flags. The audit flags high-risk tools without approval, unrestricted scopes, absent role boundaries, missing allowlist enforcement, and unsafe memory authorization policy.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | API and simulation status |
| GET | `/api/dashboard/summary` | Dashboard metrics |
| GET/POST/PUT/DELETE | `/api/targets` and `/api/targets/{id}` | Target manifest CRUD |
| POST / GET | `/api/targets/{id}/audit` | Run/read manifest permission audit |
| POST | `/api/targets/{id}/duplicate` | Clone a target as an editable version 1 |
| POST | `/api/campaigns/run` | Run bounded campaign (`target`, `target_id`, `categories`, `max_tests`, `seed`, `session_id`) |
| GET | `/api/campaigns/{id}/tree` | Persisted candidate tree |
| GET | `/api/campaigns/{id}` | Campaign, traces, and findings |
| POST | `/api/replay/run` | Recorded replay of completed source-campaign nodes |
| GET | `/api/replays`, `/api/replays/{id}` | Replay run and per-case results |
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
| GET | `/api/campaigns/{id}/export` | Download campaign evidence JSON |

API docs: <http://127.0.0.1:8000/docs>.

## Tests and build

```powershell
python -m pytest backend/tests -q --basetemp backend/.pytest-tmp
cd frontend
npm run build
```

The tests cover target seeding and audits, policy enforcement, scope-aware regressions, optional model candidate wiring, behavioral assertions across 25 regression tasks, persisted history and trace links, adaptive tree persistence, untrusted memory versioning and restore, recorded replay, and baseline/hardened corpus comparability.

## Limits

AgentBreak tests an intentionally simplified support-agent simulator. It does not run arbitrary target tools, test production agent frameworks, provide OS/container isolation, certify a real system, or send actions to third-party services. Live model/harness execution, model-turn capture, and live nondeterministic reproduction remain follow-up work.
