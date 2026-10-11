# Frontend API contracts

This inventory records the HTTP calls made by the React frontend. These routes, methods, request bodies, and response semantics are treated as immutable by the redesign. Requests use JSON through `src/api.ts` unless noted. Error responses are surfaced using the backend `detail` text when available; report downloads use the response body and `Content-Disposition` filename.

## Workspace and evidence

| Method and path | Frontend use and response fields relied on |
| --- | --- |
| `GET /api/dashboard/summary` | Overview: campaign, test, and finding totals; severity and category maps; risk score; attack-success numerator/denominator/rate; recent campaign summaries; latest validation metrics; `synthetic` scope flag. |
| `GET /api/campaigns` | Campaign history, trace picker, discovery, replay: campaign IDs, target, seed, test count, counts, risk score, creation time, and tests. |
| `GET /api/campaigns/{campaign_id}` | Completes a latest validation's baseline/hardened campaign detail when those objects are not embedded. |
| `POST /api/campaigns/run` | Creates a campaign. JSON fields used: `target`, optional `target_id`, `categories`, `max_tests`, and `seed`. Response is read for `id`, `counts`, `test_count`, `seed`, `risk_score`, `target`, and tests/traces. |
| `GET /api/campaigns/{campaign_id}/tree` | Discovery tree: `nodes` with candidate status, depth, prompt, rationale, generation method, signal, and trace ID. |
| `GET /api/campaigns/{campaign_id}/export` | Campaign JSON download via browser link. |
| `GET /api/findings` | Findings list with IDs, categories, severity, and evidence references. |
| `GET /api/findings/{finding_id}` | Finding detail; frontend expects an `evidence` object and may show the related trace. |
| `GET /api/traces/{trace_id}` | Trace detail; frontend expects an `events` array. |
| `GET /api/validations/latest` | Latest paired validation, including `metrics`, `regressions`, and possibly baseline/hardened campaign IDs or objects. |
| `GET /api/settings` | Local configuration details including campaign limits and model-adapter availability/secret-presence flags. The API does not return the secret value. |
| `POST /api/defense/validate` | Runs paired validation with no request body. Frontend reads `metrics`, `regressions`, campaign/evidence detail, and validation ID. |
| `GET /api/validations/{validation_id}/export` | Validation evidence download. |

## Targets and memory

| Method and path | Frontend use and response fields relied on |
| --- | --- |
| `GET /api/targets` | Target list with IDs, adapters, versions, and manifests. |
| `POST /api/targets` | Creates a target with JSON `{name, adapter, manifest}`. |
| `PUT /api/targets/{target_id}` | Updates a target with JSON `{name, adapter, manifest}`. |
| `POST /api/targets/{target_id}/duplicate?name=…` | Duplicates a target. Name is URL encoded. |
| `DELETE /api/targets/{target_id}` | Removes a target. |
| `POST /api/targets/{target_id}/audit` | Static manifest audit; frontend reads `findings`, target version, and finding count. These observations remain separate from executed findings. |
| `GET /api/targets/{target_id}/capabilities` | Reads target capabilities. |
| `GET /api/memory?target_id=…&session_id=…` | Reads current memory records. |
| `GET /api/memory/snapshots?target_id=…&session_id=…` | Reads saved snapshots. |
| `POST /api/memory` | Adds memory using `{target_id, session_id, key, value, trust_label, provenance}`. |
| `POST /api/memory/snapshot` | Saves a snapshot using `{target_id, session_id, label}`. |
| `DELETE /api/memory?target_id=…&session_id=…` | Clears the selected memory scope. |
| `POST /api/memory/snapshots/{snapshot_id}/restore` | Restores a saved snapshot. |
| `GET /api/memory/history?target_id=…&session_id=…&key=…` | Reads version history for a memory key. |

## Discovery, validation, replay, and regressions

| Method and path | Frontend use and response fields relied on |
| --- | --- |
| `POST /api/discovery/held-out/evaluate` | Synthetic held-out strategy evaluation using `{seed}`; reads `results`, discovered count, and scenario count. This is reported separately from campaign outcomes. |
| `POST /api/replay/run` | Replay using `{source_campaign_id, target_id, mode}` where mode is `recorded`, `reexecute`, or `live`; reads `summary` and `cases`. |
| `GET /api/replays/{replay_id}/export` | Replay JSON download. |
| `GET /api/regressions` | Regression definitions and specs. |
| `POST /api/regression/run` | Runs the default suite with no body, or an instrumented target run with `{target_id}`; frontend reads baseline/hardened tests or target tests. |
| `GET /api/regression/runs?limit=12` | Recent persisted regression run history. |
| `GET /api/regression/runs/{run_id}` | Saved regression result with a `results` array. |

## Shared request behavior

- JSON calls send `Content-Type: application/json`; successful JSON responses are parsed as returned by the backend.
- Non-success JSON calls throw an error using `detail`, or `Request failed (status)` when no detail is supplied.
- Download requests preserve backend status/error behavior and reject empty report bodies.
- The frontend does not substitute local fixture responses when any request fails.

