# ASZ Phase 3.8 — Handoff Resolver Evidence Surface Frontend Acceptance / Phase 3 UI Freeze

## Freeze status

Status: Acceptance Freeze

ASZ Phase 3.8 records acceptance of the Handoff Resolver Evidence Surface frontend implementation and freezes the Phase 3 UI evidence surface baseline.

This phase is documentation and acceptance evidence only.

This phase does not implement frontend UI, frontend routes, frontend components, storage-backed lookup, Redis lookup, Redis write, new API behavior, resolver mutation, handoff usage marking, audit mutation, trust-registry mutation, Kubernetes calls, Sentinel execution, OPA execution, token issuance, JWT issuance, runtime session creation, Agent Black Box runtime ingestion, Agent Risk Exchange runtime ingestion, SAFP federation activation, or authorization behavior.

## Repository

```text
stc-agent-sovereignty-zones-ui
Accepted frontend implementation baseline

The accepted Phase 3.7 frontend implementation is:

af1511e Add ASZ handoff resolver evidence surface

The Phase 3.7 implementation added a read-only frontend evidence surface for:

GET /v1/zones/handoff-resolver/{asz_handoff_id}

The panel displays resolver output as evidence only.

The panel does not imply authorization.

The panel does not create tokens, sessions, runtime grants, Kubernetes approvals, Sentinel outcomes, OPA results, Redis authorization, or Agent Black Box permission.

Phase 3 UI freeze scope

The following frontend evidence surfaces are preserved:

Trust Operations doctrine
Verified ≠ Authorized rule
Trust posture summary
Cross-zone handshake simulator
Trust Evidence Command Center
Zone registry evidence
Cross-zone events
Dual-zone audit chain
DDR explanations
Kubernetes/Sentinel correlation evidence
Tamper-evident audit demo
Cross-zone failure scenarios
Evidence Export preview
Handoff Resolver Evidence panel

The freeze must not remove or weaken existing ASZ doctrine.

Required safe display language

The accepted frontend evidence surface must preserve safe language including:

Resolver evidence is read-only.
Resolver output is evidence-only.
Resolved does not mean authorized.
Safe context available does not mean authorized.
ASZ does not authorize Kubernetes execution.
Sentinel/OPA remains local decision authority.
Redis is persistence, not authorization.
Resolver evidence unavailable. No authorization decision is inferred.
Forbidden display language

The accepted frontend must not display language implying:

approved execution
authorized Kubernetes
allowed the workload
granted access
issued token
created session
Kubernetes denied by ASZ
OPA denied by ASZ
Sentinel denied by ASZ
Resolver evidence display boundary

The frontend may display:

resolved
safe_context_available
reason_code
handoff evidence presence
authorization_granted_by_asz
kubernetes_execution_authorized
token_issued
session_created
redis_authorization_source
runtime_artifacts_emitted
sentinel_outcome_fabricated
opa_result_fabricated
agent_black_box_permission_granted

These fields are evidence-boundary guarantees.

They must not be displayed as permission, authorization, enforcement, execution approval, or runtime grant.

Required false guarantees

The accepted evidence surface must preserve these false guarantees:

authorization_granted_by_asz: false
kubernetes_execution_authorized: false
token_issued: false
session_created: false
redis_authorization_source: false
runtime_artifacts_emitted: false
sentinel_outcome_fabricated: false
opa_result_fabricated: false
agent_black_box_permission_granted: false
Fail-closed UI behavior

When resolver evidence is unavailable, the frontend must degrade safely.

Safe unavailable copy:

Resolver evidence unavailable. No authorization decision is inferred.

Fail-closed UI state must not be shown as:

runtime denial by ASZ
Kubernetes denial by ASZ
OPA decision
Sentinel decision
token/session decision
authorization grant
Backend and storage boundary

The Phase 3.8 UI freeze does not authorize:

storage-backed lookup
Redis lookup
Redis write
handoff usage marking
audit mutation
trust-registry mutation
new API route
new backend behavior

The existing Phase 3.4 endpoint remains intentionally read-only and fail-closed when no storage-backed evidence lookup is authorized.

Kubernetes/Sentinel boundary

ASZ frontend evidence may show Kubernetes/Sentinel correlation context.

Kubernetes/Sentinel must still perform local policy evaluation.

Sentinel/OPA remains local decision authority.

ASZ must not display Kubernetes execution as authorized by ASZ.

ASZ must not fabricate Sentinel outcomes.

ASZ must not fabricate OPA results.

Agent Black Box boundary

Agent Black Box may later consume ASZ resolver evidence as SOC evidence only.

Agent Black Box must not treat ASZ resolver evidence as:

runtime permission
Kubernetes authorization
tool-use approval
token issuance
session creation
authorization grant
Agent Risk Exchange / SAFP reference boundary

Agent Risk Exchange and SAFP may be documented as future evidence consumers only.

They may consume ASZ evidence as readiness, risk, insurance, or federation-planning evidence.

They must not treat ASZ evidence as:

live federation
agent-to-agent authentication
delegation execution
credential issuance
token issuance
session creation
revocation execution
authorization
enforcement
production activation

SAFP remains read-only planning context unless a future phase explicitly authorizes otherwise.

Ecosystem doctrine preserved
Evidence proves.
Risk scoring informs.
OPA decides.
Runtime enforces.
Frontend renders backend truth only.
LLM explains only.
RAG retrieves evidence only.
Custodian approves phase movement.
Sensitive-data exclusion

The frontend evidence surface must not expose:

private keys
signing keys
bearer tokens
JWTs
session IDs
runtime sessions
Redis credentials
raw Redis URLs
authorization headers
raw TLS keys
secret values
unredacted customer payloads
provider API keys
production certificates
Acceptance validation commands

The acceptance validation commands for this freeze are:

npm run build

grep -n "Handoff Resolver Evidence\|Resolver evidence is read-only\|Resolver output is evidence-only\|Resolved does not mean authorized\|Safe context available does not mean authorized\|ASZ does not authorize Kubernetes execution\|Sentinel/OPA remains local decision authority\|Redis is persistence, not authorization\|Resolver evidence unavailable\|No authorization decision is inferred" app/page.tsx

grep -n "approved execution\|authorized Kubernetes\|allowed the workload\|granted access\|issued token\|created session\|Kubernetes denied by ASZ\|OPA denied by ASZ\|Sentinel denied by ASZ" app/page.tsx

Required result:

frontend build passes
required safe language appears
forbidden language grep returns no output
only documentation is added in Phase 3.8
Out-of-scope behavior

Phase 3.8 does not implement:

frontend UI changes
frontend route changes
frontend component changes
backend changes
storage-backed lookup
Redis lookup
Redis write
new API behavior
resolver mutation
handoff usage marking
audit mutation
trust-registry mutation
Kubernetes call
Sentinel execution
OPA execution
token issuance
JWT issuance
runtime session creation
Agent Black Box runtime ingestion
Agent Risk Exchange runtime ingestion
SAFP live federation
authorization behavior
production enforcement
Allowed next phase

After Phase 3.8 is committed, the governed next ASZ phase is:

ASZ Phase 3.9 — Handoff Resolver Storage-Backed Evidence Lookup Gate

Phase 3.9 must be gate/contract first.

Phase 3.9 must not implement Redis lookup until the storage-backed boundary is explicitly defined.

Any future storage-backed resolver phase must preserve:

read-only mode
non-enforcing mode
evidence-only output
fail-closed missing evidence
fail-closed expired evidence
fail-closed replay evidence
fail-closed tampered evidence
no Redis-as-authorization
no token/session behavior
no Kubernetes calls
no Sentinel/OPA execution
no authorization behavior
no fabricated outcomes
Completion criteria

Phase 3.8 is complete when:

frontend build evidence is recorded
required safe copy is verified
forbidden authorization copy is absent
Phase 3 frontend evidence surface is frozen
Agent Black Box / ARE / SAFP consumer boundaries are documented
backend and storage boundaries remain unchanged
working tree is clean after commit

Phase 3.8 must not add frontend or runtime behavior.
