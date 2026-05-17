"use client";

import { type FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  Fingerprint,
  GitBranch,
  Globe2,
  KeyRound,
  Layers3,
  LockKeyhole,
  Network,
  ServerCog,
  FileCheck2,
  AlertTriangle,
  RefreshCcw,
  XCircle,
} from "lucide-react";

type TrustZoneRecord = {
  zone_id: string;
  display_name?: string;
  status: "trusted" | "suspended" | "revoked" | string;
  verification_key?: string;
  kid?: string;
  allowed_intents?: string[];
  allowed_destination_zones?: string[];
  created_at?: string;
  updated_at?: string;
};

type TrustRegistryResponse = {
  read_only: true;
  count: number;
  zones: Record<string, TrustZoneRecord>;
};

type ZoneEvent = {
  event_id: string;
  event_type: string;
  zone_id: string;
  source_zone: string;
  destination_zone: string;
  assertion_id: string;
  principal?: string | null;
  intent?: string | null;
  outcome: string;
  reason_code?: string | null;
  timestamp: string;
  previous_hash: string;
  event_hash: string;
  metadata?: Record<string, unknown>;
};

type EventsResponse = {
  read_only: true;
  count: number;
  events: ZoneEvent[];
};

type AuditResponse = EventsResponse & {
  chain_verified: boolean;
  latest_hash: string;
};

type TamperDemoResponse = {
  read_only: true;
  tamper_demo: true;
  original_chain_verified: boolean;
  tampered_chain_verified: boolean;
  tampered_event_id?: string | null;
  tampered_field?: string | null;
  tamper_description: string;
  events: ZoneEvent[];
};

type FailureDemoScenario = "invalid_signature" | "replay_attempt";

type FailureDemoResponse = {
  demo_only: true;
  scenario: FailureDemoScenario;
  expected_result: "rejected";
  assertion_id: string;
  status_code: number;
  reason_code: string;
  event_type: string;
  failure_event_id?: string | null;
  audit_recorded: boolean;
  local_opa_handoff: false;
  authorization_granted: false;
  trust_registry_mutated: false;
};

type Explanation = {
  decision_type: string;
  outcome: "ALLOW" | "DENY" | "INVALID" | string;
  reason_code: string;
  summary: string;
  explanation: string;
  operator_action: string;
  local_decision_authority: "OPA" | string;
  authorization_status: string;
  metadata?: Record<string, unknown>;
};

type ExplanationsResponse = {
  read_only: true;
  count: number;
  explanations: Explanation[];
};

type CorrelationAuditAnchor = {
  event_id: string;
  event_hash: string;
  previous_hash: string;
};

type CorrelationASZEvidence = {
  verified: boolean;
  status: string;
  origin_zone: string;
  destination_zone: string;
  principal?: string | null;
  intent?: string | null;
  audit_anchor: CorrelationAuditAnchor;
};

type CorrelationSentinelEvidence = {
  evidence_available: boolean;
  status: "pending_sentinel_evidence" | "sentinel_evidence_unavailable" | "sentinel_evidence_available" | string;
  decision_authority: "OPA" | string;
  authorization_status: "requires_local_opa_decision" | string;
  outcome?: "ALLOW" | "DENY" | "REVIEW" | null;
  reason_code?: string | null;
};

type CorrelationProof = {
  opa_authority_preserved: true;
  asz_authorization_bypass: false;
  authorization_granted_by_asz: false;
  redis_authorization_source: false;
  runtime_artifacts_emitted: false;
};

type KubernetesCorrelationResponse = {
  read_only: true;
  correlation_type: "asz_kubernetes_sentinel" | string;
  generated_at: string;
  tenant_id?: string | null;
  source: "asz_backend" | string;
  found: boolean;
  reason_code?: "asz_evidence_not_found" | "sentinel_evidence_unavailable" | string | null;
  assertion_id: string;
  asz_handoff_id?: string | null;
  asz?: CorrelationASZEvidence | null;
  sentinel: CorrelationSentinelEvidence;
  proof: CorrelationProof;
};

type KubernetesCorrelationSummaryResponse = {
  read_only: true;
  correlation_type: "asz_kubernetes_sentinel" | string;
  generated_at: string;
  tenant_id?: string | null;
  source: "asz_backend" | string;
  count: number;
  correlations: KubernetesCorrelationResponse[];
  proof: CorrelationProof;
};

type HandoffResolverProof = {
  authorization_granted_by_asz: false;
  kubernetes_execution_authorized: false;
  token_issued: false;
  session_created: false;
  redis_authorization_source: false;
  sentinel_outcome_fabricated: false;
  opa_result_fabricated: false;
  agent_black_box_permission_granted: false;
  runtime_artifacts_emitted: false;
};

type HandoffResolverResponse = {
  resolved: boolean;
  safe_context_available: boolean;
  reason_code?: string | null;
  handoff?: unknown | null;
  proof: HandoffResolverProof;
};

type OutboundHandshakeResponse = {
  status: "assertion_created" | string;
  assertion_id: string;
  expires_at: number;
  envelope: Record<string, unknown>;
};

type InboundHandshakeResponse = {
  status: "verified_requires_local_opa_decision" | string;
  assertion_id: string;
  origin_zone: string;
  destination_zone: string;
  runtime_contract: {
    tenant_id: string;
    principal: string;
    intent: string;
    scopes: string[];
    ttl_seconds: number;
    context: Record<string, unknown>;
    local_decision_authority: "OPA" | string;
    authorization_status: "requires_local_opa_decision" | string;
  };
  warning: string;
};

type HandshakeResult = {
  outbound?: OutboundHandshakeResponse;
  inbound?: InboundHandshakeResponse;
};

type DashboardState = {
  registry?: TrustRegistryResponse;
  events?: EventsResponse;
  audit?: AuditResponse;
  tamperDemo?: TamperDemoResponse;
  explanations?: ExplanationsResponse;
  correlationSummary?: KubernetesCorrelationSummaryResponse;
  handoffResolver?: HandoffResolverResponse;
};

const EVENTS_VISIBLE_LIMIT = 6;
const AUDIT_VISIBLE_LIMIT = 6;
const EXPLANATIONS_VISIBLE_LIMIT = 5;
const CORRELATIONS_VISIBLE_LIMIT = 4;

const API_BASE = process.env.NEXT_PUBLIC_ASZ_API_BASE_URL || "";
const API_KEY = process.env.NEXT_PUBLIC_ASZ_TENANT_API_KEY || "";

function headers(): HeadersInit {
  const base: HeadersInit = { "Content-Type": "application/json" };
  if (API_KEY) {
    base["X-STC-Tenant-Api-Key"] = API_KEY;
  }
  return base;
}

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: headers(),
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error(`${path} failed with ${res.status}`);
  }

  return res.json() as Promise<T>;
}

async function postJson<T>(path: string, payload: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(payload),
    cache: "no-store",
  });

  if (!res.ok) {
    let detail = `${path} failed with ${res.status}`;

    try {
      const body = await res.json();
      if (body?.detail) {
        detail = `${detail}: ${body.detail}`;
      }
    } catch {
      // Keep deterministic fallback detail.
    }

    throw new Error(detail);
  }

  return res.json() as Promise<T>;
}

function shortHash(value?: string | null) {
  if (!value) return "—";
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function statusClass(status?: string) {
  if (status === "trusted" || status === "accepted" || status === "ALLOW" || status === "verified_requires_local_opa_decision") return "text-emerald-300 bg-emerald-400/10 border-emerald-400/20";
  if (status === "suspended" || status === "created" || status === "pending_sentinel_evidence" || status === "sentinel_evidence_unavailable") return "text-amber-300 bg-amber-400/10 border-amber-400/20";
  if (status === "revoked" || status === "rejected" || status === "DENY" || status === "INVALID") return "text-rose-300 bg-rose-400/10 border-rose-400/20";
  return "text-sky-300 bg-sky-400/10 border-sky-400/20";
}

function Badge({ children }: { children?: React.ReactNode }) {
  return (
    <span className="inline-flex rounded-full border border-cyan-300/30 bg-cyan-300/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-200">
      {children}
    </span>
  );
}

function YesNoPill({ value, positive = true }: { value: boolean; positive?: boolean }) {
  const text = value ? "True" : "False";
  const cls = value === positive ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-200" : "border-rose-400/30 bg-rose-400/10 text-rose-200";
  return <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${cls}`}>{text}</span>;
}

function CTAButtons() {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <Link
        href="https://securethecloud.dev/request-demo"
        className="group inline-flex items-center justify-center rounded-full bg-gradient-to-r from-sky-400 to-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-[0_0_40px_rgba(56,189,248,0.28)] transition hover:scale-[1.02]"
      >
        Request Private Demo
        <ArrowRight className="ml-2 h-4 w-4 transition group-hover:translate-x-1" />
      </Link>
      <Link
        href="mailto:ola.omoniyi@securethecloud.dev?subject=ASZ%20Architecture%20Review"
        className="inline-flex items-center justify-center rounded-full border border-slate-500/40 bg-slate-900/60 px-6 py-3 text-sm font-semibold text-slate-100 transition hover:border-sky-300/70 hover:bg-slate-800"
      >
        Schedule Architecture Review
      </Link>
    </div>
  );
}

function ShellHeader({ connected }: { connected: boolean }) {
  const controlItems = ["Overview", "Trust Ops", "Registry", "Handshake", "Audit", "DDR", "Failures"];
  const supportItems = ["Observability", "Handoff", "Export"];

  return (
    <header className="sticky top-0 z-30 border-b border-sky-400/20 bg-[#020914]/95 shadow-2xl shadow-black/30 backdrop-blur">
      <div className="border-b border-sky-400/20 bg-[#102949] px-4 py-2 text-xs text-sky-100">
        Trust Operations Mode · ASZ → Registry → Assertions → Audit → DDR → Sentinel Handoff → Evidence
      </div>
      <div className="mx-auto flex max-w-[1440px] flex-col gap-6 px-6 py-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-4">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-amber-300 to-yellow-500 text-slate-950 shadow-[0_0_30px_rgba(250,204,21,0.18)]">
            <LockKeyhole className="h-6 w-6" />
          </div>
          <div>
            <div className="text-xl font-black tracking-tight text-white">
              Secure<span className="text-amber-300">TheCloud</span>
            </div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Agent Sovereignty Zones</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs font-semibold text-slate-300">
          <span className={`inline-flex items-center rounded-full border px-4 py-2 ${connected ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-200" : "border-amber-400/20 bg-amber-400/10 text-amber-200"}`}>
            <span className={`mr-2 h-2 w-2 rounded-full ${connected ? "bg-emerald-400" : "bg-amber-300"}`} />
            {connected ? "Backend Connected" : "Backend Pending"}
          </span>
          <span className="rounded-full border border-slate-700 bg-slate-900 px-4 py-2 text-slate-400">
            Local OPA Required
          </span>
        </div>
      </div>

      <nav className="mx-auto flex max-w-[1440px] flex-col gap-4 px-6 pb-5 text-sm md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <span className="mr-2 text-xs font-bold uppercase tracking-[0.28em] text-slate-500">Control</span>
          {controlItems.map((item, index) => (
            <a
              key={item}
              href={index === 0 ? "#overview" : item === "Handshake" ? "#handshake" : item === "Registry" ? "#evidence" : "#evidence"}
              className={`rounded-full px-3 py-2 transition hover:bg-sky-400/10 hover:text-sky-200 ${index === 1 ? "bg-sky-400/10 text-sky-200 ring-1 ring-sky-400/20" : "text-slate-300"}`}
            >
              {item}
            </a>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="mr-2 text-xs font-bold uppercase tracking-[0.28em] text-slate-500">Support</span>
          {supportItems.map((item) => (
            <a key={item} href="#evidence" className="rounded-full px-3 py-2 text-slate-300 transition hover:bg-sky-400/10 hover:text-sky-200">
              {item}
            </a>
          ))}
        </div>
      </nav>
    </header>
  );
}

function StatusPanel({ audit }: { audit?: AuditResponse }) {
  return (
    <div className="rounded-3xl border border-slate-700/60 bg-slate-950/75 p-6">
      <div className="mb-6 flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Trust operations rule</p>
          <h3 className="mt-1 text-lg font-semibold text-white">Verified ≠ Authorized</h3>
        </div>
        <span className="rounded-full bg-amber-300/10 px-3 py-1 text-xs font-semibold text-amber-200">OPA REQUIRED</span>
      </div>
      <div className="space-y-3">
        {[
          ["Trust registry", "Eligibility checked", "text-sky-300"],
          ["CIPHER signature", "Integrity verified", "text-sky-300"],
          ["Audit chain", audit?.chain_verified ? "Verified" : "Pending data", audit?.chain_verified ? "text-emerald-300" : "text-amber-300"],
          ["Sentinel handoff", "Local OPA remains final", "text-amber-300"],
        ].map(([label, value, color]) => (
          <div key={label} className="flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-sm">
            <span className="text-slate-400">{label}</span>
            <span className={`font-semibold ${color}`}>{value}</span>
          </div>
        ))}
      </div>
      <div className="mt-5 rounded-2xl border border-amber-300/20 bg-amber-300/10 p-4 text-sm leading-6 text-amber-100">
        ASZ verified context may be handed to Sentinel/Kubernetes. Sentinel/OPA remains the local enforcement authority.
      </div>
    </div>
  );
}

function Hero({ audit }: { audit?: AuditResponse }) {
  return (
    <section id="overview" className="relative overflow-hidden px-6 pb-14 pt-10 md:pb-16 md:pt-12">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_20%,rgba(56,189,248,0.18),transparent_34%),radial-gradient(circle_at_80%_30%,rgba(37,99,235,0.14),transparent_32%)]" />
      <div className="relative mx-auto grid max-w-7xl gap-6">
        <div className="rounded-[1.75rem] border border-sky-400/20 bg-[#10243f]/80 p-6 shadow-2xl shadow-black/20 md:p-8 lg:p-10">
          <p className="mb-6 text-xs font-bold uppercase tracking-[0.28em] text-slate-400">Platform Overview</p>
          <div className="grid gap-8 lg:grid-cols-[1fr_0.42fr] lg:items-end">
            <div>
              <Badge>Agent Sovereignty Zones Command Center</Badge>
              <h1 className="mt-7 text-4xl font-black leading-[1.02] tracking-[-0.05em] text-white md:text-6xl lg:text-7xl">
                ASZ Trust Operations Platform
              </h1>
              <p className="mt-6 max-w-4xl text-base leading-8 text-slate-300 md:text-xl">
                Operate cross-zone agent trust with signed assertions, deterministic failure explanations, tamper-evident audit history, and local enforcement handoff visibility.
              </p>
            </div>
            <div className="rounded-3xl border border-slate-700/60 bg-slate-950/60 p-5">
              <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Command Rule</p>
              <p className="mt-3 text-2xl font-black text-white">Verified ≠ Authorized</p>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                ASZ provides verified handoff context. Sentinel/OPA remains the receiving-zone decision authority.
              </p>
            </div>
          </div>
          <div className="mt-8 flex flex-col justify-between gap-6 border-t border-slate-700/70 pt-6 lg:flex-row lg:items-center">
            <CTAButtons />
            <div className="grid gap-3 text-sm leading-6 text-slate-300 sm:grid-cols-3 lg:max-w-3xl">
              <div className="rounded-2xl border border-slate-700/60 bg-slate-950/50 p-4">
                <Fingerprint className="mb-3 h-5 w-5 text-cyan-300" />
                Signed assertions cross zones as evidence, not execution approval.
              </div>
              <div className="rounded-2xl border border-slate-700/60 bg-slate-950/50 p-4">
                <KeyRound className="mb-3 h-5 w-5 text-sky-300" />
                Trust, signature, replay, and DDR proof remain independently inspectable.
              </div>
              <div className="rounded-2xl border border-slate-700/60 bg-slate-950/50 p-4">
                <LockKeyhole className="mb-3 h-5 w-5 text-amber-300" />
                Local OPA remains required before any receiving-zone action proceeds.
              </div>
            </div>
          </div>
        </div>

        <StatusPanel audit={audit} />
      </div>
    </section>
  );
}

function isRejectedEvent(event: ZoneEvent) {
  return (
    event.outcome === "rejected" ||
    event.outcome === "DENY" ||
    event.outcome === "INVALID" ||
    Boolean(event.reason_code?.includes("SIGNATURE") || event.reason_code?.includes("REPLAY"))
  );
}

function TrustPostureSummary({ state }: { state: DashboardState }) {
  const zones = Object.values(state.registry?.zones || {});
  const trustedZones = zones.filter((zone) => zone.status === "trusted").length;
  const events = state.events?.events || [];
  const rejectedHandoffs = events.filter(isRejectedEvent).length;
  const auditVerified = state.audit?.chain_verified === true;
  const tamperDetected = state.tamperDemo?.tampered_chain_verified === false;
  const latestCorrelation = latestCorrelationFromSummary(state.correlationSummary);

  const cards = [
    {
      icon: Globe2,
      label: "Trusted Zones",
      value: `${trustedZones}/${state.registry?.count ?? zones.length}`,
      detail: "Trust registry entries currently marked trusted.",
    },
    {
      icon: Network,
      label: "Live Events",
      value: `${state.events?.count ?? events.length}`,
      detail: "Cross-zone records loaded from the backend evidence stream.",
    },
    {
      icon: GitBranch,
      label: "Audit Chain",
      value: auditVerified ? "Verified" : "Pending",
      detail: auditVerified ? "Latest hash chain verification is passing." : "Waiting for audit data or backend verification.",
    },
    {
      icon: XCircle,
      label: "Rejected Handoffs",
      value: `${rejectedHandoffs}`,
      detail: "Derived from rejected, invalid, deny, signature, and replay evidence.",
    },
    {
      icon: AlertTriangle,
      label: "Tamper Proof",
      value: tamperDetected ? "Detected" : "Pending",
      detail: tamperDetected ? "Cloned-chain tamper simulation breaks as expected." : "Safe simulation has not returned tamper evidence yet.",
    },
    {
      icon: ServerCog,
      label: "K8s Correlation",
      value: latestCorrelation?.sentinel.status === "sentinel_evidence_available" ? "Available" : "Pending",
      detail: "Correlation is evidence-only. ASZ does not authorize Kubernetes execution.",
    },
  ];

  return (
    <section className="border-y border-slate-800/80 bg-[#07101d] px-6 py-12">
      <div className="mx-auto max-w-7xl">
        <div className="mb-6 flex flex-col justify-between gap-3 rounded-[1.75rem] border border-sky-400/20 bg-[#10243f]/70 p-6 md:flex-row md:items-end">
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.28em] text-sky-300">Trust posture summary</p>
            <h2 className="text-2xl font-bold tracking-tight text-white md:text-4xl">Executive Trust Posture</h2>
          </div>
          <p className="max-w-2xl text-sm leading-6 text-slate-400">
            A compact operations view of trust registry state, evidence volume, audit integrity, rejection proof, tamper evidence, and local enforcement posture.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {cards.map(({ icon: Icon, label, value, detail }) => (
            <div key={label} className="rounded-3xl border border-sky-400/20 bg-[#10243f]/75 p-5 shadow-xl shadow-black/10">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-sky-300/20 bg-sky-300/10 text-sky-300">
                  <Icon className="h-5 w-5" />
                </div>
                <span className="text-right text-2xl font-bold text-white">{value}</span>
              </div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">{label}</p>
              <p className="mt-3 text-xs leading-5 text-slate-400">{detail}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function HandshakeSimulator({ onComplete }: { onComplete: () => Promise<void> }) {
  const [originZone, setOriginZone] = useState("zone-a");
  const [destinationZone, setDestinationZone] = useState("zone-b");
  const [principal, setPrincipal] = useState("agent-demo");
  const [intent, setIntent] = useState("zone:handoff");
  const [scopeText, setScopeText] = useState("zone:handoff");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<HandshakeResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runHandshake(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setRunning(true);
    setError(null);
    setResult(null);

    try {
      const scopes = scopeText
        .split(",")
        .map((scope) => scope.trim())
        .filter(Boolean);

      const outbound = await postJson<OutboundHandshakeResponse>(
        "/v1/zones/handshake/outbound",
        {
          origin_zone: originZone,
          destination_zone: destinationZone,
          principal,
          intent,
          scopes,
          context: {
            source: "asz-platform-ui",
          },
          ttl_seconds: 120,
          policy_revision: "asz-ui-demo-1",
        }
      );

      const inbound = await postJson<InboundHandshakeResponse>(
        "/v1/zones/handshake/inbound",
        {
          envelope: outbound.envelope,
        }
      );

      setResult({ outbound, inbound });
      await onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Handshake failed.");
      await onComplete();
    } finally {
      setRunning(false);
    }
  }

  return (
    <section id="handshake" className="border-y border-slate-800/80 bg-[#05070d] px-6 py-20">
      <div className="mx-auto max-w-7xl">
        <div className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.28em] text-sky-300">
              Handshake simulator
            </p>
            <h2 className="text-3xl font-bold tracking-tight text-white md:text-5xl">
              Run Cross-Zone Handshake
            </h2>
            <p className="mt-4 max-w-3xl text-base leading-8 text-slate-300">
              Create a signed outbound assertion, submit it to the inbound verifier, then refresh the live evidence panels without clearing audit history.
            </p>
          </div>
          <div className="rounded-full border border-amber-300/20 bg-amber-300/10 px-4 py-2 text-xs font-semibold text-amber-200">
            Verified ≠ Authorized
          </div>
        </div>

        <div className="grid gap-5 lg:grid-cols-[0.9fr_1.1fr]">
          <form
            onSubmit={runHandshake}
            className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5"
          >
            <div className="grid gap-4 md:grid-cols-2">
              <label className="text-sm font-medium text-slate-300">
                Origin Zone
                <input
                  value={originZone}
                  onChange={(event) => setOriginZone(event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-white outline-none focus:border-sky-300"
                />
              </label>

              <label className="text-sm font-medium text-slate-300">
                Destination Zone
                <input
                  value={destinationZone}
                  onChange={(event) => setDestinationZone(event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-white outline-none focus:border-sky-300"
                />
              </label>

              <label className="text-sm font-medium text-slate-300">
                Principal
                <input
                  value={principal}
                  onChange={(event) => setPrincipal(event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-white outline-none focus:border-sky-300"
                />
              </label>

              <label className="text-sm font-medium text-slate-300">
                Intent
                <input
                  value={intent}
                  onChange={(event) => setIntent(event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-white outline-none focus:border-sky-300"
                />
              </label>

              <label className="text-sm font-medium text-slate-300 md:col-span-2">
                Scopes
                <input
                  value={scopeText}
                  onChange={(event) => setScopeText(event.target.value)}
                  className="mt-2 w-full rounded-2xl border border-slate-700 bg-slate-900 px-4 py-3 text-white outline-none focus:border-sky-300"
                  placeholder="zone:handoff, evidence:read"
                />
              </label>
            </div>

            <button
              type="submit"
              disabled={running}
              className="mt-5 inline-flex w-full items-center justify-center rounded-full bg-gradient-to-r from-sky-400 to-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-[0_0_40px_rgba(56,189,248,0.22)] transition hover:scale-[1.01] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {running ? "Running Cross-Zone Handshake..." : "Run Cross-Zone Handshake"}
              <ArrowRight className="ml-2 h-4 w-4" />
            </button>
          </form>

          <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Handshake Result</h3>
              <span className="rounded-full border border-amber-300/20 bg-amber-300/10 px-3 py-1 text-xs font-semibold text-amber-200">
                Local OPA Required
              </span>
            </div>

            {error ? (
              <div className="rounded-2xl border border-rose-400/20 bg-rose-400/10 p-4 text-sm leading-6 text-rose-100">
                <div className="mb-2 flex items-center gap-2 font-semibold">
                  <XCircle className="h-4 w-4" />
                  Handshake rejected
                </div>
                {error}
                <p className="mt-2 text-rose-100/75">
                  Rejected before local OPA. No runtime authorization granted.
                </p>
              </div>
            ) : null}

            {result?.inbound ? (
              <div className="space-y-3">
                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-4">
                  <p className="text-sm font-semibold text-emerald-200">
                    Verified for local OPA evaluation — not execution approval.
                  </p>
                  <p className="mt-2 text-xs leading-5 text-emerald-100/80">
                    Assertion {result.inbound.assertion_id} moved from {result.inbound.origin_zone} to {result.inbound.destination_zone}.
                  </p>
                </div>

                <div className="grid gap-3 md:grid-cols-2">
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
                    <p className="text-slate-500">Outbound</p>
                    <p className="mt-1 font-semibold text-white">{result.outbound?.status}</p>
                    <p className="mt-1 text-slate-400">expires_at: {result.outbound?.expires_at}</p>
                  </div>

                  <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
                    <p className="text-slate-500">Inbound</p>
                    <p className="mt-1 font-semibold text-white">{result.inbound.status}</p>
                    <p className="mt-1 text-slate-400">
                      authority: {result.inbound.runtime_contract.local_decision_authority}
                    </p>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs leading-5 text-slate-300">
                  {result.inbound.warning}
                </div>
              </div>
            ) : !error ? (
              <div className="rounded-2xl border border-dashed border-slate-700 p-5 text-sm leading-6 text-slate-500">
                Run a handshake to create live events, DDR explanations, and audit-chain records.
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </section>
  );
}

function PanelHeader({ eyebrow, title, meta }: { eyebrow: string; title: string; meta?: React.ReactNode }) {
  return (
    <div className="mb-4 flex flex-col justify-between gap-3 md:flex-row md:items-center">
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.22em] text-sky-300">{eyebrow}</p>
        <h3 className="text-lg font-semibold text-white">{title}</h3>
      </div>
      {meta ? <div>{meta}</div> : null}
    </div>
  );
}

function PlaceholderPanel({ icon: Icon, title, body }: { icon: any; title: string; body: string }) {
  return (
    <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200">
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">Preview</p>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
        </div>
      </div>
      <p className="text-sm leading-6 text-slate-300">{body}</p>
      <div className="mt-5 rounded-2xl border border-dashed border-slate-700 p-4 text-xs leading-5 text-slate-500">
        Read-only evidence export APIs are backend-ready. Frontend export actions remain disabled until explicitly enabled.
      </div>
    </div>
  );
}

function latestCorrelationFromSummary(summary?: KubernetesCorrelationSummaryResponse) {
  const correlations = summary?.correlations || [];
  return correlations.length ? correlations[correlations.length - 1] : undefined;
}

function DataPanel({ state, loading, error, onRefresh }: { state: DashboardState; loading: boolean; error: string | null; onRefresh: () => void | Promise<void> }) {
  const zones = useMemo(() => Object.values(state.registry?.zones || {}), [state.registry]);
  const events = state.events?.events || [];
  const auditEvents = state.audit?.events || [];
  const tamperDemo = state.tamperDemo;
  const explanations = state.explanations?.explanations || [];
  const correlations = state.correlationSummary?.correlations || [];

  const visibleEvents = events.slice(-EVENTS_VISIBLE_LIMIT).reverse();
  const visibleAuditEvents = auditEvents.slice(-AUDIT_VISIBLE_LIMIT).reverse();
  const visibleExplanations = explanations.slice(-EXPLANATIONS_VISIBLE_LIMIT).reverse();
  const visibleCorrelations = correlations.slice(-CORRELATIONS_VISIBLE_LIMIT).reverse();

  const [failureRunning, setFailureRunning] = useState<FailureDemoScenario | null>(null);
  const [failureResult, setFailureResult] = useState<FailureDemoResponse | null>(null);
  const [failureError, setFailureError] = useState<string | null>(null);

  async function runFailureScenario(scenario: FailureDemoScenario) {
    setFailureRunning(scenario);
    setFailureError(null);
    setFailureResult(null);

    try {
      const result = await postJson<FailureDemoResponse>(
        "/v1/zones/handshake/failure-demo",
        { scenario }
      );

      setFailureResult(result);
      await Promise.resolve(onRefresh());
    } catch (err) {
      setFailureError(err instanceof Error ? err.message : "Failure scenario failed.");
      await Promise.resolve(onRefresh());
    } finally {
      setFailureRunning(null);
    }
  }

  return (
    <section id="evidence" className="border-y border-slate-800/80 bg-[#080b14] px-6 py-20 md:py-28">
      <div className="mx-auto max-w-7xl">
        <div className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.28em] text-sky-300">Live backend visibility</p>
            <h2 className="text-3xl font-bold tracking-tight text-white md:text-5xl">Trust Evidence Command Center</h2>
            <p className="mt-4 max-w-3xl text-base leading-8 text-slate-300">
              Operational evidence from the Agent Sovereignty Zones backend: registry posture, cross-zone events, hash-linked audit proof, DDR explanations, safe tamper simulation, deterministic failure evidence, and Kubernetes/Sentinel correlation.
            </p>
          </div>
          <button
            onClick={onRefresh}
            className="inline-flex items-center justify-center rounded-full border border-slate-600 bg-slate-900 px-5 py-3 text-sm font-semibold text-white transition hover:border-sky-300"
          >
            <RefreshCcw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>

        {error ? (
          <div className="mb-6 rounded-3xl border border-rose-400/20 bg-rose-400/10 p-5 text-sm leading-6 text-rose-100">
            <div className="mb-2 flex items-center gap-2 font-semibold"><XCircle className="h-4 w-4" /> Backend connection issue</div>
            {error}
            <p className="mt-2 text-rose-100/75">Set NEXT_PUBLIC_ASZ_API_BASE_URL and tenant API key configuration for live deployment.</p>
          </div>
        ) : null}

        <div className="grid gap-5 lg:grid-cols-2">
          <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
            <PanelHeader
              eyebrow="Registry"
              title="Zone Registry"
              meta={<span className="text-xs text-slate-500">{state.registry?.count ?? 0} zones</span>}
            />
            <div className="space-y-3">
              {zones.length ? zones.map((zone) => (
                <div key={zone.zone_id} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="font-semibold text-white">{zone.display_name || zone.zone_id}</p>
                      <p className="text-xs text-slate-500">kid: {zone.kid || "—"}</p>
                    </div>
                    <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${statusClass(zone.status)}`}>{zone.status}</span>
                  </div>
                  <p className="mt-3 text-xs leading-5 text-slate-400">Intents: {(zone.allowed_intents || []).join(", ") || "—"}</p>
                  <p className="text-xs leading-5 text-slate-400">Destinations: {(zone.allowed_destination_zones || []).join(", ") || "—"}</p>
                </div>
              )) : <Empty label="No registry records returned" />}
            </div>
          </div>

          <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
            <PanelHeader
              eyebrow="Activity"
              title="Cross-Zone Events"
              meta={(
                <span className="text-xs text-slate-500">
                  {events.length > visibleEvents.length
                    ? `Showing latest ${visibleEvents.length} of ${events.length} events`
                    : `${state.events?.count ?? 0} events`}
                </span>
              )}
            />
            <div className="space-y-3">
              {visibleEvents.length ? visibleEvents.map((event) => <EventRow key={event.event_id} event={event} />) : <Empty label="No events returned" />}
            </div>
          </div>

          <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
            <PanelHeader
              eyebrow="Audit integrity"
              title="Dual-Zone Audit Chain"
              meta={(
                <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${state.audit?.chain_verified ? statusClass("accepted") : statusClass("created")}`}>
                  {state.audit?.chain_verified ? "Verified" : "Pending"}
                </span>
              )}
            />
            <div className="mb-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs text-slate-400">
              Latest hash: <span className="font-mono text-slate-200">{shortHash(state.audit?.latest_hash)}</span>
              <p className="mt-2 text-slate-500">
                {auditEvents.length > visibleAuditEvents.length
                  ? `Showing latest ${visibleAuditEvents.length} of ${auditEvents.length} audit records`
                  : `${auditEvents.length} audit records`}
              </p>
            </div>
            <div className="space-y-3">
              {visibleAuditEvents.length ? visibleAuditEvents.map((event) => <HashRow key={event.event_id} event={event} />) : <Empty label="No audit records returned" />}
            </div>
          </div>

          <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
            <PanelHeader
              eyebrow="Deterministic decision record"
              title="DDR Explanations"
              meta={(
                <span className="text-xs text-slate-500">
                  {explanations.length > visibleExplanations.length
                    ? `Showing latest ${visibleExplanations.length} of ${explanations.length} explanations`
                    : `${state.explanations?.count ?? 0} explanations`}
                </span>
              )}
            />
            <div className="space-y-3">
              {visibleExplanations.length ? visibleExplanations.map((item, index) => <ExplanationRow key={`${item.reason_code}-${index}`} item={item} />) : <Empty label="No explanations returned" />}
            </div>
          </div>

          <KubernetesSentinelCorrelationPanel
            summary={state.correlationSummary}
            visibleCorrelations={visibleCorrelations}
          />

          <div className="rounded-3xl border border-rose-400/30 bg-rose-950/30 p-5 lg:col-span-2">
            <div className="mb-4 flex flex-col justify-between gap-3 md:flex-row md:items-center">
              <div>
                <div className="mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-rose-300" />
                  <h3 className="text-lg font-semibold text-white">Tamper-Evident Audit Demo</h3>
                </div>
                <p className="max-w-4xl text-sm leading-6 text-rose-100/75">
                  Safe simulation: ASZ creates a temporary copy of the audit chain, changes one field in that copy,
                  and verifies that the copied chain breaks. The real Redis-backed audit chain remains unchanged and verified.
                </p>
              </div>
              <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                tamperDemo?.tampered_chain_verified === false
                  ? "border-rose-400/30 bg-rose-400/10 text-rose-200"
                  : "border-amber-400/30 bg-amber-400/10 text-amber-200"
              }`}>
                {tamperDemo?.tampered_chain_verified === false ? "Tamper Simulation Detected" : "Pending Demo"}
              </span>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Real Audit Chain</p>
                <p className={`mt-2 text-sm font-semibold ${tamperDemo?.original_chain_verified ? "text-emerald-300" : "text-rose-300"}`}>
                  {tamperDemo?.original_chain_verified ? "Verified" : "Unverified"}
                </p>
              </div>

              <div className="rounded-2xl border border-rose-400/20 bg-rose-400/10 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-rose-200/70">Simulated Tampered Copy</p>
                <p className={`mt-2 text-sm font-semibold ${tamperDemo?.tampered_chain_verified === false ? "text-rose-200" : "text-amber-200"}`}>
                  {tamperDemo?.tampered_chain_verified === false ? "Broken Hash Chain" : "Pending"}
                </p>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Field Changed in Copy</p>
                <p className="mt-2 text-sm font-semibold text-white">
                  {tamperDemo?.tampered_field || "—"}
                </p>
              </div>
            </div>

            <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-4 text-xs leading-5 text-slate-300">
              <p>
                Cloned event tested:{" "}
                <span className="font-mono text-rose-200">
                  {shortHash(tamperDemo?.tampered_event_id)}
                </span>
              </p>
              <p className="mt-2 text-slate-400">
                Only the cloned audit event was modified for this demo. The persisted Redis audit chain was not changed.
              </p>
              <p className="mt-2 text-slate-500">
                Refresh behavior: Refresh re-runs the safe simulation against the latest persisted audit chain. It does not clear audit history.
              </p>
            </div>
          </div>

          <div className="rounded-3xl border border-amber-400/30 bg-amber-950/20 p-5 lg:col-span-2">
            <div className="mb-5 flex flex-col justify-between gap-3 md:flex-row md:items-center">
              <div>
                <div className="mb-2 flex items-center gap-2">
                  <XCircle className="h-5 w-5 text-amber-300" />
                  <h3 className="text-lg font-semibold text-white">Cross-Zone Failure Scenarios</h3>
                </div>
                <p className="max-w-4xl text-sm leading-6 text-amber-100/75">
                  Valid assertions can cross zones. Invalid assertions fail closed before local OPA.
                  ASZ records the rejection, explains the reason, and produces no runtime grant.
                </p>
              </div>
              <span className="rounded-full border border-amber-400/30 bg-amber-400/10 px-3 py-1 text-xs font-semibold text-amber-200">
                Fail Closed Demo
              </span>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">Invalid Signature</p>
                    <p className="mt-2 text-xs leading-5 text-slate-400">
                      Simulates a modified assertion payload. CIPHER integrity rejects it before local OPA.
                    </p>
                  </div>
                  <span className="rounded-full border border-rose-400/30 bg-rose-400/10 px-3 py-1 text-xs font-semibold text-rose-200">
                    401
                  </span>
                </div>
                <button
                  type="button"
                  disabled={failureRunning !== null}
                  onClick={() => runFailureScenario("invalid_signature")}
                  className="mt-4 inline-flex w-full items-center justify-center rounded-full border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm font-semibold text-rose-100 transition hover:bg-rose-400/20 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {failureRunning === "invalid_signature" ? "Running Invalid Signature..." : "Run Invalid Signature Demo"}
                </button>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">Replay Attempt</p>
                    <p className="mt-2 text-xs leading-5 text-slate-400">
                      Simulates reusing the same assertion ID. Replay protection rejects the duplicate handoff.
                    </p>
                  </div>
                  <span className="rounded-full border border-rose-400/30 bg-rose-400/10 px-3 py-1 text-xs font-semibold text-rose-200">
                    409
                  </span>
                </div>
                <button
                  type="button"
                  disabled={failureRunning !== null}
                  onClick={() => runFailureScenario("replay_attempt")}
                  className="mt-4 inline-flex w-full items-center justify-center rounded-full border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm font-semibold text-rose-100 transition hover:bg-rose-400/20 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {failureRunning === "replay_attempt" ? "Running Replay Attempt..." : "Run Replay Attempt Demo"}
                </button>
              </div>
            </div>

            {failureError ? (
              <div className="mt-4 rounded-2xl border border-rose-400/20 bg-rose-400/10 p-4 text-xs leading-5 text-rose-100">
                {failureError}
              </div>
            ) : null}

            {failureResult ? (
              <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-4 text-xs leading-5 text-slate-300">
                <div className="grid gap-3 md:grid-cols-4">
                  <div>
                    <p className="uppercase tracking-[0.2em] text-slate-500">Scenario</p>
                    <p className="mt-1 font-semibold text-white">{failureResult.scenario}</p>
                  </div>
                  <div>
                    <p className="uppercase tracking-[0.2em] text-slate-500">Reason</p>
                    <p className="mt-1 font-semibold text-amber-200">{failureResult.reason_code}</p>
                  </div>
                  <div>
                    <p className="uppercase tracking-[0.2em] text-slate-500">Audit Event</p>
                    <p className="mt-1 font-semibold text-white">{failureResult.event_type}</p>
                  </div>
                  <div>
                    <p className="uppercase tracking-[0.2em] text-slate-500">Outcome</p>
                    <p className="mt-1 font-semibold text-rose-200">{failureResult.expected_result}</p>
                  </div>
                </div>

                <div className="mt-4 grid gap-3 md:grid-cols-4">
                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                    <p className="text-slate-500">Audit recorded</p>
                    <p className="mt-1 font-semibold text-emerald-300">{failureResult.audit_recorded ? "Yes" : "No"}</p>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                    <p className="text-slate-500">Local OPA handoff</p>
                    <p className="mt-1 font-semibold text-rose-200">{failureResult.local_opa_handoff ? "Yes" : "No"}</p>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                    <p className="text-slate-500">Runtime grant</p>
                    <p className="mt-1 font-semibold text-rose-200">{failureResult.authorization_granted ? "Yes" : "No"}</p>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                    <p className="text-slate-500">Trust registry mutated</p>
                    <p className="mt-1 font-semibold text-rose-200">{failureResult.trust_registry_mutated ? "Yes" : "No"}</p>
                  </div>
                </div>

                <p className="mt-4 text-slate-500">
                  Failure demos write rejection evidence to the audit chain. They do not corrupt Redis, mutate the trust registry, create sessions, or create runtime grants.
                </p>
              </div>
            ) : (
              <div className="mt-4 rounded-2xl border border-dashed border-slate-700 p-4 text-xs leading-5 text-slate-500">
                Run a failure scenario to prove invalid trust is rejected, recorded, and explained.
              </div>
            )}
          </div>

          <PlaceholderPanel
            icon={FileCheck2}
            title="Evidence Export"
            body="Future evidence bundles will package assertion details, DDR explanations, audit anchors, failure evidence, and handoff correlation without exposing secrets, tokens, or private keys."
          />

        <HandoffResolverEvidencePanel resolver={state.handoffResolver} />
        </div>
      </div>
    </section>
  );
}


function HandoffResolverEvidencePanel({
  resolver,
}: {
  resolver?: HandoffResolverResponse;
}) {
  const proof = resolver?.proof;

  const evidenceCell = (label: string, value: string) => (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</p>
      <p className="mt-2 text-sm font-semibold text-white">{value}</p>
    </div>
  );

  return (
    <section className="rounded-3xl border border-slate-800 bg-slate-900/60 p-5 shadow-2xl shadow-black/20">
      <PanelHeader
        eyebrow="Handoff Resolver Evidence"
        title="Read-only resolver evidence"
        meta={
          <span className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs font-semibold text-cyan-200">
            Evidence-only
          </span>
        }
      />

      <p className="mt-4 text-sm leading-6 text-slate-300">
        Resolver evidence is read-only. Resolver output is evidence-only.
        Resolved does not mean authorized. Safe context available does not mean authorized.
        ASZ does not authorize Kubernetes execution. Sentinel/OPA remains local decision authority.
        Redis is persistence, not authorization.
      </p>

      {!resolver ? (
        <p className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/70 p-4 text-sm text-slate-400">
          Resolver evidence unavailable. No authorization decision is inferred.
        </p>
      ) : (
        <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {evidenceCell("Resolved", resolver.resolved ? "True" : "False")}
          {evidenceCell("Safe context", resolver.safe_context_available ? "True" : "False")}
          {evidenceCell("Reason", resolver.reason_code ?? "none")}
          {evidenceCell("Handoff evidence", resolver.handoff ? "Present" : "Unavailable")}
        </div>
      )}

      {proof && (
        <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {evidenceCell("ASZ authorization granted", proof.authorization_granted_by_asz ? "True" : "False")}
          {evidenceCell("Kubernetes execution authorized", proof.kubernetes_execution_authorized ? "True" : "False")}
          {evidenceCell("Token issued", proof.token_issued ? "True" : "False")}
          {evidenceCell("Session created", proof.session_created ? "True" : "False")}
          {evidenceCell("Redis authorization source", proof.redis_authorization_source ? "True" : "False")}
          {evidenceCell("Runtime artifacts emitted", proof.runtime_artifacts_emitted ? "True" : "False")}
          {evidenceCell("Sentinel outcome fabricated", proof.sentinel_outcome_fabricated ? "True" : "False")}
          {evidenceCell("OPA result fabricated", proof.opa_result_fabricated ? "True" : "False")}
          {evidenceCell("Agent Black Box permission granted", proof.agent_black_box_permission_granted ? "True" : "False")}
        </div>
      )}
    </section>
  );
}

function KubernetesSentinelCorrelationPanel({
  summary,
  visibleCorrelations,
}: {
  summary?: KubernetesCorrelationSummaryResponse;
  visibleCorrelations: KubernetesCorrelationResponse[];
}) {
  const latest = latestCorrelationFromSummary(summary);
  const count = summary?.count ?? 0;

  return (
    <div className="rounded-3xl border border-cyan-300/30 bg-cyan-950/20 p-5 lg:col-span-2">
      <PanelHeader
        eyebrow="Kubernetes/Sentinel Handoff"
        title="Live Correlation View"
        meta={(
          <span className="rounded-full border border-amber-300/20 bg-amber-300/10 px-3 py-1 text-xs font-semibold text-amber-200">
            OPA authority preserved
          </span>
        )}
      />

      <div className="mb-5 rounded-2xl border border-amber-300/20 bg-amber-300/10 p-4 text-sm leading-6 text-amber-100">
        ASZ can provide verified handoff context to Sentinel. Sentinel still evaluates the local Kubernetes action with OPA as the decision authority.
        <span className="mt-2 block font-semibold">Correlation is evidence-only. ASZ does not authorize Kubernetes execution.</span>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">ASZ assertion verified</p>
          <p className={`mt-2 text-sm font-semibold ${latest?.asz?.verified ? "text-emerald-300" : "text-amber-300"}`}>
            {latest?.asz?.verified ? "Verified" : latest ? "Not verified" : "Pending evidence"}
          </p>
          <p className="mt-2 text-xs text-slate-500">{latest?.asz?.status || "No ASZ correlation record loaded"}</p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">ASZ handoff context</p>
          <p className={`mt-2 text-sm font-semibold ${latest?.asz_handoff_id ? "text-emerald-300" : "text-amber-300"}`}>
            {latest?.asz_handoff_id ? "Available" : "Pending"}
          </p>
          <p className="mt-2 font-mono text-xs text-slate-500">{latest?.asz_handoff_id || "No asz_handoff_id in current evidence"}</p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Sentinel evidence</p>
          <p className={`mt-2 text-sm font-semibold ${latest?.sentinel.evidence_available ? "text-emerald-300" : "text-amber-300"}`}>
            {latest?.sentinel.evidence_available ? "Available" : "Pending / unavailable"}
          </p>
          <p className="mt-2 text-xs text-slate-500">{latest?.sentinel.status || "pending_sentinel_evidence"}</p>
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">OPA authority preserved</p>
            <YesNoPill value={latest?.proof.opa_authority_preserved ?? summary?.proof.opa_authority_preserved ?? true} />
          </div>
          <p className="mt-2 text-xs text-slate-400">Sentinel/OPA remains the local decision authority.</p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">ASZ authorization bypass</p>
            <YesNoPill value={latest?.proof.asz_authorization_bypass ?? false} positive={false} />
          </div>
          <p className="mt-2 text-xs text-slate-400">The correlation proof keeps bypass false.</p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">ASZ authorization granted</p>
            <YesNoPill value={latest?.proof.authorization_granted_by_asz ?? false} positive={false} />
          </div>
          <p className="mt-2 text-xs text-slate-400">ASZ evidence is not an execution approval.</p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Redis authorization source</p>
            <YesNoPill value={latest?.proof.redis_authorization_source ?? summary?.proof.redis_authorization_source ?? false} positive={false} />
          </div>
          <p className="mt-2 text-xs text-slate-400">Redis is persistence, not authorization authority.</p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Runtime artifacts emitted</p>
            <YesNoPill value={latest?.proof.runtime_artifacts_emitted ?? summary?.proof.runtime_artifacts_emitted ?? false} positive={false} />
          </div>
          <p className="mt-2 text-xs text-slate-400">Correlation does not issue tokens, sessions, or runtime grants.</p>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Correlation records</p>
            <p className="mt-1 text-sm font-semibold text-white">
              {count > visibleCorrelations.length
                ? `Showing latest ${visibleCorrelations.length} of ${count} correlations`
                : `${count} correlations`}
            </p>
          </div>
          <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${statusClass(latest?.sentinel.status || "pending_sentinel_evidence")}`}>
            {latest?.sentinel.status || "pending_sentinel_evidence"}
          </span>
        </div>

        <div className="space-y-3">
          {visibleCorrelations.length ? visibleCorrelations.map((correlation) => (
            <CorrelationRow key={correlation.assertion_id} correlation={correlation} />
          )) : <Empty label="No Kubernetes/Sentinel correlation records returned" />}
        </div>
      </div>
    </div>
  );
}

function CorrelationRow({ correlation }: { correlation: KubernetesCorrelationResponse }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs leading-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="font-semibold text-white">Assertion {shortHash(correlation.assertion_id)}</p>
          <p className="mt-1 text-slate-500">
            {correlation.asz?.origin_zone || "—"} → {correlation.asz?.destination_zone || "—"}
          </p>
        </div>
        <span className={`rounded-full border px-3 py-1 font-semibold ${statusClass(correlation.sentinel.status)}`}>
          {correlation.sentinel.status}
        </span>
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-4">
        <div>
          <p className="uppercase tracking-[0.2em] text-slate-500">ASZ verified</p>
          <p className={correlation.asz?.verified ? "font-semibold text-emerald-300" : "font-semibold text-amber-300"}>
            {correlation.asz?.verified ? "true" : "false"}
          </p>
        </div>
        <div>
          <p className="uppercase tracking-[0.2em] text-slate-500">Sentinel outcome</p>
          <p className="font-semibold text-slate-300">{correlation.sentinel.outcome || "not fabricated"}</p>
        </div>
        <div>
          <p className="uppercase tracking-[0.2em] text-slate-500">Decision authority</p>
          <p className="font-semibold text-amber-200">{correlation.sentinel.decision_authority}</p>
        </div>
        <div>
          <p className="uppercase tracking-[0.2em] text-slate-500">Audit anchor</p>
          <p className="font-mono text-slate-300">{shortHash(correlation.asz?.audit_anchor.event_id)}</p>
        </div>
      </div>
    </div>
  );
}

function Empty({ label }: { label: string }) {
  return <div className="rounded-2xl border border-dashed border-slate-700 p-5 text-sm text-slate-500">{label}</div>;
}

function EventRow({ event }: { event: ZoneEvent }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm font-semibold text-white">{event.event_type}</p>
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${statusClass(event.outcome)}`}>{event.outcome}</span>
      </div>
      <p className="mt-2 text-xs text-slate-400">{event.source_zone} → {event.destination_zone}</p>
      <p className="mt-1 text-xs text-slate-500">{event.intent || "—"} · {event.timestamp}</p>
      {event.reason_code ? <p className="mt-2 text-xs font-semibold text-amber-300">{event.reason_code}</p> : null}
    </div>
  );
}

function HashRow({ event }: { event: ZoneEvent }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs">
      <p className="font-semibold text-white">{event.event_type}</p>
      <p className="mt-2 text-slate-400">event_hash: <span className="font-mono text-slate-200">{shortHash(event.event_hash)}</span></p>
      <p className="mt-1 text-slate-400">previous_hash: <span className="font-mono text-slate-200">{shortHash(event.previous_hash)}</span></p>
    </div>
  );
}

function ExplanationRow({ item }: { item: Explanation }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm font-semibold text-white">{item.reason_code}</p>
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${statusClass(item.outcome)}`}>
          {item.reason_code === "ASSERTION_VERIFIED_LOCAL_OPA_REQUIRED" ? "VERIFIED" : item.outcome}
        </span>
      </div>
      <p className="mt-3 text-sm leading-6 text-slate-300">{item.summary}</p>
      <p className="mt-2 text-xs leading-5 text-slate-500">{item.operator_action}</p>
    </div>
  );
}

export default function AgentSovereigntyZonesPage() {
  const [state, setState] = useState<DashboardState>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadDashboard() {
    setLoading(true);
    setError(null);
    try {
      const [registry, events, audit, tamperDemo, explanations] = await Promise.all([
        fetchJson<TrustRegistryResponse>("/v1/zones/trust-registry"),
        fetchJson<EventsResponse>("/v1/zones/events"),
        fetchJson<AuditResponse>("/v1/zones/audit"),
        fetchJson<TamperDemoResponse>("/v1/zones/audit/tamper-demo"),
        fetchJson<ExplanationsResponse>("/v1/zones/explanations"),
      ]);

      let correlationSummary: KubernetesCorrelationSummaryResponse | undefined;

      try {
        correlationSummary = await fetchJson<KubernetesCorrelationSummaryResponse>("/v1/zones/correlation/summary");
      } catch {
        correlationSummary = undefined;
      }

      let handoffResolver: HandoffResolverResponse | undefined;
      try {
        handoffResolver = await fetchJson<HandoffResolverResponse>(
          "/v1/zones/handoff-resolver/demo-handoff?destination_zone=zone-b&requested_by=asz-frontend"
        );
      } catch {
        handoffResolver = undefined;
      }

      setState({ registry, events, audit, tamperDemo, explanations, correlationSummary, handoffResolver });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load ASZ backend visibility.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();
  }, []);

  return (
    <main className="min-h-screen bg-[#05070d] text-slate-100">
      <ShellHeader connected={!error && Boolean(state.registry || state.events || state.audit)} />
      <Hero audit={state.audit} />
      <TrustPostureSummary state={state} />
      <HandshakeSimulator onComplete={loadDashboard} />
      <DataPanel state={state} loading={loading} error={error} onRefresh={loadDashboard} />
      <section className="px-6 py-20 md:py-28">
        <div className="mx-auto max-w-5xl rounded-[2rem] border border-sky-300/20 bg-[radial-gradient(circle_at_top,rgba(56,189,248,0.18),transparent_38%),#07101d] p-8 text-center md:p-14">
          <Layers3 className="mx-auto mb-6 h-10 w-10 text-sky-300" />
          <h2 className="text-4xl font-bold tracking-tight text-white md:text-6xl">
            Trust Operations for Cross-Zone Agent Governance
          </h2>
          <p className="mx-auto mt-6 max-w-3xl text-lg leading-8 text-slate-300">
            Use this command center to demonstrate live handshakes, rejection proof, deterministic explanations, audit integrity, and local enforcement handoff visibility without changing backend behavior.
          </p>
          <div className="mt-9 flex justify-center"><CTAButtons /></div>
        </div>
      </section>
    </main>
  );
}
