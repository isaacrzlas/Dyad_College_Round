AgentBreak
Discover. Trace. Defend. Validate.
A reproducible red-team workbench for testing AI-agent security failures, inspecting attack evidence, and validating defensive policies.
AgentBreak demonstrates how malicious instructions in user prompts, retrieved documents, or session memory can influence an AI-style support workflow and lead to unauthorized tool actions. It runs controlled adversarial tests against deliberately vulnerable and hardened agent simulators, records the execution evidence, and evaluates whether security improvements preserve legitimate functionality.
Instead of reporting only that an attack succeeded or failed, AgentBreak exposes the chain of events behind the result: the input, retrieved content, memory state, agent decision, proposed tool call, authorization decision, and resulting action.
All demonstrations use synthetic data and registered mock tools. AgentBreak is designed to make agent security failures observable, reproducible, and testable.

The Problem
AI agents do more than generate text. They interpret instructions, retrieve information, maintain memory, and propose actions through tools. This creates security risks that ordinary functional tests may miss.
An agent can produce a reasonable-looking response while following an instruction embedded in an untrusted document, using information outside its intended scope, or proposing an unauthorized action.
Testing the final response alone does not explain how that failure happened.
AgentBreak addresses this by evaluating the behavior between input and outcome, preserving evidence that developers can inspect and replay, and comparing vulnerable behavior with stricter defensive policies.
How It Works
AgentBreak follows a four-stage workflow:
1. Discover → 2. Trace → 3. Defend → 4. Validate
1.Discover: Generate a bounded, reproducible set of adversarial test candidates using predefined scenarios, deterministic mutations, trace-driven follow-ups, and optional model-assisted candidate generation.
2.Trace: Record the execution path, including untrusted inputs, retrieval and memory events, decisions, proposed tools, authorization outcomes, and synthetic side effects.
3.Defend: Evaluate the same eligible attack candidates against a hardened target with stricter trust, permission, scope, and approval policies.
4.Validate: Compare the two target configurations and run legitimate-workflow regressions to check whether the security controls preserve expected behavior.
The resulting findings, traces, campaign trees, regression results, and validation evidence are persisted in SQLite and can be inspected or exported.
Architecture
flowchart TD
    A[Adversarial Inputs] --> B[Bounded Candidate Generator]
    B --> C[Synthetic Agent Simulator]
    C --> D[Retrieval and Session Memory]
    D --> E[Agent Decision and Tool Proposal]
    E --> F[Central Authorization Dispatcher]
    F --> G{Policy Decision}
    G -->|Allowed| H[Synthetic Tool Execution]
    G -->|Denied| I[Blocked Action]
    H --> J[Trace and Evidence Store]
    I --> J
    J --> K[Findings and Discovery Tree]
    J --> L[Replay and Defense Validation]
    L --> M[Hardened Target Comparison]
    L --> N[Legitimate Workflow Regressions]
    M --> O[Metrics and Evidence Export]
    N --> O
Technology stack
Layer	Technology
Frontend	React, TypeScript, Vite
Backend	Python, FastAPI
Persistence	SQLite
Testing	pytest, local mocked HTTP endpoints
Optional model integration	OpenAI-compatible chat-completions API
The backend owns the simulator state machine, registered synthetic tools, authorization dispatcher, persistence, evidence generation, and evaluation logic. The frontend provides the workbench for configuring targets, launching campaigns, inspecting traces, comparing defenses, and reviewing regression results.
Key Features
Adversarial Campaigns
Run bounded campaigns with reproducible seeds and configurable test budgets.
Generate candidates from predefined scenarios and deterministic mutations.
Use observed trace signals to schedule bounded follow-up probes.
Persist candidate rationale, parent-child relationships, outcomes, and linked traces.
Distinguish predefined, deterministic, feedback-driven, and model-generated candidates.
Multi-Stage Attack Traces
Inspect the sequence behind a simulated security failure:
Attacker-controlled input.
Retrieved content and trust labels.
Target- and session-scoped memory.
Intermediate decisions and proposed tool calls.
Authorization decisions and policy outcomes.
Synthetic side effects and final results.
This makes it possible to investigate the relationship between an untrusted instruction and a subsequent action instead of relying exclusively on the final response.
Tool and Permission Auditing
AgentBreak uses target manifests to describe tool availability, risk, roles, permissions, resource scopes, approval requirements, and policy settings.
Its central authorization dispatcher checks proposed actions against the applicable controls before allowing synthetic side effects. A separate static manifest audit identifies configuration risks such as unrestricted scopes, missing role boundaries, or high-risk tools without approval requirements.
Static configuration findings are distinguished from evidence of an action that actually executed.
Replay and Reproducibility
AgentBreak supports distinct replay workflows:
Recorded reconstruction: Reconstructs persisted trace events without invoking the target or repeating side effects.
Fresh simulator re-execution: Runs saved candidate inputs against a selected simulator target and stores new evidence linked to the source trace.
Fresh model rerun: Listed as a separate mode, but currently unavailable; the live replay endpoint returns HTTP 501.
Saved inputs, candidate relationships, traces, and outcomes support repeatable investigations under controlled simulator conditions.
Defense Validation
Freeze an eligible baseline candidate corpus.
Replay equivalent attack inputs against the hardened simulator.
Preserve target configuration versions and case-level outcomes.
Compare security results using explicit denominators.
Run legitimate-task regressions alongside attack-focused tests.
Export paired validation evidence for independent inspection.
Errors, skipped cases, and inconclusive outcomes remain distinct from successful defenses.
Behavioral Regression Testing
The project includes 25 regression task definitions with explicit initial state, operation, expected outcome, side-effect constraints, and behavioral assertions.
Results use five statuses:
passed
failed
skipped
errored
inconclusive
This helps distinguish a security control that blocks an unsafe action from a workflow that genuinely completes as expected.
Memory and Snapshots
AgentBreak supports target- and session-scoped synthetic memory, including trust labels, provenance, version history, snapshots, restoration, and reset operations.
A snapshot captures the selected session’s memory state only. It does not snapshot campaigns, target settings, documents, or the entire database. Snapshots are persisted in SQLite so a saved memory state can be restored for reproducible testing.
Evidence and Exports
Inspect and export persisted campaign and validation evidence, including candidate data, case outcomes, regression results, and trace events.
The dashboard provides access to:
Overview
Campaigns
Findings
Traces
Discovery Tree
Defense Lab
Replay Lab
Regression
Targets
Memory
Settings

Run AgentBreak Locally
AgentBreak is designed to run locally without paid API credentials. The guided demo uses the built-in synthetic targets.
Prerequisites
Python 3.10 or later
Node.js 20 or later
npm
1. Clone the repository
git clone https://github.com/isaacrzlas/Dyad_College_Round.git
cd Dyad_College_Round
2. Install backend dependencies
From the repository root:
python -m pip install -r backend/requirements.txt
3. Start the backend
python -m uvicorn app:app --app-dir backend --reload --host 127.0.0.1 --port 8000
The API will be available at http://127.0.0.1:8000.
Verify the service at http://127.0.0.1:8000/api/health.
Interactive API documentation is available at http://127.0.0.1:8000/docs.
4. Install frontend dependencies
Open a second terminal:
cd frontend
npm install
npm run dev
Open http://127.0.0.1:5173 in your browser.
5. Run the guided demonstration
Select Run Guided Demo from the dashboard.
The credential-free workflow demonstrates a synthetic exploit, hardened replay, benign regressions, and a saved comparison. Follow the resulting campaign, findings, and traces to inspect the evidence, then review the defensive validation and regression results.
Note: The demo executes a fresh local simulator workflow. It does not connect to an external AI agent or a live production system.

Optional Model-Assisted Candidate Generation
AgentBreak can use an OpenAI-compatible chat-completions endpoint to propose additional adversarial candidate text and follow-ups.
Configure the following environment variables in the backend environment:
LLM_BASE_URL=<your-compatible-endpoint>
LLM_MODEL=<your-model-name>
LLM_API_KEY=<your-api-key>
LLM_API_KEY is optional for endpoints that do not require authentication. Keep credentials server-side and never commit real secrets to the repository.
This integration is optional. Without it, the local synthetic workflow and test suite do not require a paid provider.
Important: Model-assisted candidate generation is not the same as executing an external target agent. Generated candidates remain untrusted inputs and are evaluated through the local simulator and authorization path. Genuine external-provider behavior has not been verified as part of the documented acceptance testing.

API Reference
The FastAPI service exposes endpoints for the primary product workflows.
Area	Representative endpoints
Health and dashboard	GET /api/health, GET /api/dashboard/summary
Target management	/api/targets, /api/targets/{id}
Target auditing	/api/targets/{id}/audit, /api/targets/{id}/capabilities
Campaigns	POST /api/campaigns/run, GET /api/campaigns/{id}
Discovery tree	GET /api/campaigns/{id}/tree
Findings and traces	/api/findings, /api/traces/{id}
Replay	POST /api/replay/run, /api/replays/{id}
Defense validation	POST /api/defense/validate
Regression testing	POST /api/regression/run, /api/regression/runs/{id}
Synthetic memory	/api/memory, /api/memory/history
Memory snapshots	/api/memory/snapshot, /api/memory/snapshots
Snapshot restoration	POST /api/memory/snapshots/{id}/restore
Validation exports	/api/validations/{id}/export
Campaign exports	/api/campaigns/{id}/export
Replay exports	/api/replays/{id}/export
The complete, interactive request and response schemas are available through the local Swagger UI at /docs.
Testing and Build
Run the backend test suite from the repository root:
python -m pytest backend/tests -q --basetemp backend/.pytest-tmp
Build the frontend:
cd frontend
npm run build
The backend tests cover policy enforcement, target manifests and audits, regression assertions, memory versioning and restoration, campaign and replay persistence, trace relationships, evidence exports, secret redaction, restart persistence, and paired baseline/hardened comparisons.
The optional model adapter is tested using a local mocked endpoint, so the automated test suite does not require paid provider access.
Run these commands on your current checkout to verify the latest code before presenting the project. Test results can change as the repository evolves.
Data and Configuration
By default, AgentBreak stores its SQLite database at:
backend/agentbreak.sqlite3
To use a different database path, set AGENTBREAK_DB in the backend environment before starting the service.
Keep local database files and real credentials out of version control. Use isolated test databases when running tests, and avoid deleting the normal application database to reset test state.
Security Model and Limitations
AgentBreak is a controlled, application-level simulation, not a production security sandbox.
All identities, records, documents, tickets, memory, and email effects are synthetic.
Only supported simulator targets execute. Other adapter labels can be stored and audited but are not general external-agent integrations.
The built-in vulnerable target deliberately models weak policy behavior to demonstrate controlled failures.
The hardened target demonstrates stricter policy behavior under equivalent synthetic test conditions.
The optional model integration proposes candidate text; it does not expose another agent’s private state or run its tools.
The application does not provide operating-system or container isolation for arbitrary untrusted workloads.
The project does not connect to real customer systems, send real email, execute shell commands, or invoke arbitrary external tools.
External-provider behavior and live target-agent execution have not been verified in the documented acceptance run.
Adaptive discovery is bounded and simulator-specific; it should not be described as unrestricted autonomous vulnerability discovery.
Understanding the Evidence
Evidence type	What it demonstrates
Simulated execution evidence	An action was allowed or denied in the synthetic execution, with supporting trace events.
Static manifest audit	A declared configuration has a potential permission or policy weakness.
Mocked adapter test	Code behaves as expected against a controlled local test endpoint.
External deployment evidence	Not established by the current implementation.
AgentBreak’s findings and metrics describe the tested simulator and saved evidence. They are not external benchmarks, proof of a real-world vulnerability, or certification that a deployed AI agent is secure.

Project Status
AgentBreak currently provides a working local workflow for bounded adversarial testing, trace inspection, synthetic tool authorization, deterministic simulator replay, paired defense validation, behavioral regression testing, and persisted evidence exports.
The main areas for further development are broader evidence-driven adaptive discovery, stronger automated frontend testing, richer causal trace comparisons, and safely scoped integrations with externally instrumented agents.
Future integrations should preserve the central authorization boundary, reproducibility, complete trace evidence, and explicit separation between simulated and externally verified results.
Team and Project
AgentBreak was developed as a college-round hackathon project for the AI-agent security-testing problem statement.
Repository: isaacrzlas/Dyad_College_Round
The project aims to make AI-agent security testing more transparent by showing not only whether a controlled attack succeeds, but what happened, why the policy allowed or denied it, and whether the defensive change preserves legitimate behavior.

AgentBreak is a research and demonstration workbench. Use it to evaluate controlled synthetic scenarios, not as a substitute for a security assessment of a production system.
