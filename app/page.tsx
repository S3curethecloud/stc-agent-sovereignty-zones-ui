"use client";

import { type FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
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
  Database,
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
  explanations?: ExplanationsResponse;
};

const productPillars = [
  {
    icon: Globe2,
    title: "Sovereign Governance Domains",
    body: "Each organization runs its own SecureTheCloud Aegis Runtime with independent policy, risk, audit, and decision authority.",
  },
  {
    icon: KeyRound,
    title: "Signed Agent Assertions",
    body: "Cross-zone requests carry signed assertions derived from local runtime truth, not unaudited agent claims.",
  },
  {
    icon: LockKeyhole,
    title: "Local Re-Evaluation",
    body: "The receiving zone verifies the assertion, checks trust, and still requires local OPA evaluation before execution.",
  },
  {
    icon: FileCheck2,
    title: "Deterministic Explanation",
    body: "DDR explains every verification, denial, replay failure, signature failure, and local handoff outcome without generic AI guessing.",
  },
  {
    icon: GitBranch,
    title: "Dual-Zone Audit Anchoring",
    body: "Both zones can record hash-linked audit events so cross-domain autonomous activity remains provable.",
  },
  {
    icon: ServerCog,
    title: "Runtime-Ready Integration",
    body: "A verified cross-zone contract can be adapted into the existing Aegis Runtime token issue path where OPA remains final.",
  },
];

const handshakeSteps = [
  "Zone A creates a signed assertion",
  "Zone B checks ATLAS trust registry",
  "CIPHER verifies assertion integrity",
  "Replay and timestamp protections run",
  "BRIDGE builds a local runtime contract",
  "Aegis Runtime sends the request to local OPA",
];

const useCases = [
  "Vendor AI agents requesting governed access into enterprise workflows",
  "Bank, insurance, and claims agents exchanging verifiable handoff context",
  "Multi-cloud agent systems coordinating across independent runtime domains",
  "Partner ecosystems where each organization retains its own governance authority",
];

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
  if (status === "trusted" || status === "accepted" || status === "ALLOW") return "text-emerald-300 bg-emerald-400/10 border-emerald-400/20";
  if (status === "suspended" || status === "created") return "text-amber-300 bg-amber-400/10 border-amber-400/20";
  if (status === "revoked" || status === "rejected" || status === "DENY" || status === "INVALID") return "text-rose-300 bg-rose-400/10 border-rose-400/20";
  return "text-sky-300 bg-sky-400/10 border-sky-400/20";
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex rounded-full border border-cyan-300/30 bg-cyan-300/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-200">
      {children}
    </span>
  );
}

function SectionHeader({ eyebrow, title, body }: { eyebrow?: string; title: string; body?: string }) {
  return (
    <div className="mx-auto mb-12 max-w-3xl text-center">
      {eyebrow ? <p className="mb-3 text-xs font-semibold uppercase tracking-[0.28em] text-sky-300">{eyebrow}</p> : null}
      <h2 className="text-3xl font-bold tracking-tight text-white md:text-5xl">{title}</h2>
      {body ? <p className="mt-5 text-base leading-8 text-slate-300 md:text-lg">{body}</p> : null}
    </div>
  );
}

function Card({ icon: Icon, title, body }: { icon: any; title: string; body: string }) {
  return (
    <div className="rounded-3xl border border-slate-700/50 bg-slate-900/50 p-6 shadow-xl shadow-black/10 transition hover:border-sky-300/40 hover:bg-slate-900/75">
      <div className="mb-5 flex h-11 w-11 items-center justify-center rounded-2xl border border-sky-300/20 bg-sky-300/10 text-sky-300">
        <Icon className="h-5 w-5" />
      </div>
      <h3 className="text-xl font-semibold text-white">{title}</h3>
      <p className="mt-3 text-sm leading-7 text-slate-300">{body}</p>
    </div>
  );
}

function CTAButtons() {
  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <Link
        href="/request-demo"
        className="group inline-flex items-center justify-center rounded-full bg-gradient-to-r from-sky-400 to-blue-600 px-6 py-3 text-sm font-semibold text-white shadow-[0_0_40px_rgba(56,189,248,0.28)] transition hover:scale-[1.02]"
      >
        Request Private Demo
        <ArrowRight className="ml-2 h-4 w-4 transition group-hover:translate-x-1" />
      </Link>
      <Link
        href="/architecture-review"
        className="inline-flex items-center justify-center rounded-full border border-slate-500/40 bg-slate-900/60 px-6 py-3 text-sm font-semibold text-slate-100 transition hover:border-sky-300/70 hover:bg-slate-800"
      >
        Schedule Architecture Review
      </Link>
    </div>
  );
}

function ZoneDiagram() {
  const left = ["Aegis Runtime", "OPA Authority", "RiskDNA", "DDR Explainer", "Audit Chain"];
  const right = ["Trust Registry", "Signature Verification", "Replay Protection", "Local Runtime Contract", "Local OPA Required"];

  return (
    <div className="rounded-[2rem] border border-sky-300/20 bg-[#070b16] p-5 shadow-2xl shadow-sky-950/30">
      <div className="grid gap-5 lg:grid-cols-[1fr_0.36fr_1fr]">
        <div className="rounded-3xl border border-slate-700/60 bg-slate-950/75 p-5">
          <div className="mb-5 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Zone A</h3>
            <span className="rounded-full bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-300">Sovereign</span>
          </div>
          <div className="space-y-3">
            {left.map((item) => (
              <div key={item} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3 text-sm font-medium text-slate-200">
                {item}
              </div>
            ))}
          </div>
        </div>

        <div className="flex flex-col items-center justify-center gap-4 rounded-3xl border border-cyan-300/20 bg-cyan-300/10 p-5 text-center">
          <Fingerprint className="h-8 w-8 text-cyan-200" />
          <p className="text-sm font-semibold text-white">Signed Assertion</p>
          <p className="text-xs leading-5 text-cyan-100/80">hash + signature + nonce + policy context</p>
          <ArrowRight className="hidden h-6 w-6 text-cyan-200 lg:block" />
        </div>

        <div className="rounded-3xl border border-slate-700/60 bg-slate-950/75 p-5">
          <div className="mb-5 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Zone B</h3>
            <span className="rounded-full bg-sky-400/10 px-3 py-1 text-xs font-semibold text-sky-300">Independent</span>
          </div>
          <div className="space-y-3">
            {right.map((item) => (
              <div key={item} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-3 text-sm font-medium text-slate-200">
                {item}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusPanel({ audit }: { audit?: AuditResponse }) {
  return (
    <div className="rounded-3xl border border-slate-700/60 bg-slate-950/75 p-6">
      <div className="mb-6 flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-slate-500">ASZ Decision Contract</p>
          <h3 className="mt-1 text-lg font-semibold text-white">Verified ≠ Authorized</h3>
        </div>
        <span className="rounded-full bg-amber-300/10 px-3 py-1 text-xs font-semibold text-amber-200">OPA REQUIRED</span>
      </div>
      <div className="space-y-3">
        {[
          ["Trust registry", "ATLAS eligibility required", "text-sky-300"],
          ["Signature", "CIPHER integrity required", "text-sky-300"],
          ["Audit chain", audit?.chain_verified ? "Verified" : "Pending data", audit?.chain_verified ? "text-emerald-300" : "text-amber-300"],
          ["Runtime", "Forward to local OPA only", "text-amber-300"],
        ].map(([label, value, color]) => (
          <div key={label} className="flex items-center justify-between rounded-2xl border border-slate-800 bg-slate-900/70 px-4 py-3 text-sm">
            <span className="text-slate-400">{label}</span>
            <span className={`font-semibold ${color}`}>{value}</span>
          </div>
        ))}
      </div>
      <div className="mt-5 rounded-2xl border border-amber-300/20 bg-amber-300/10 p-4 text-sm leading-6 text-amber-100">
        Verified for local OPA evaluation — not execution approval.
      </div>
    </div>
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
    <section className="border-y border-slate-800/80 bg-[#05070d] px-6 py-20">
      <div className="mx-auto max-w-7xl">
        <div className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.28em] text-sky-300">
              Live handshake simulator
            </p>
            <h2 className="text-3xl font-bold tracking-tight text-white md:text-5xl">
              Generate Cross-Zone Activity
            </h2>
            <p className="mt-4 max-w-3xl text-base leading-8 text-slate-300">
              Create a signed outbound assertion, submit it to the inbound verifier, then refresh events, DDR explanations, and the audit chain.
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
                  placeholder="zone:handoff, agent:execute"
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

function DataPanel({ state, loading, error, onRefresh }: { state: DashboardState; loading: boolean; error: string | null; onRefresh: () => void }) {
  const zones = useMemo(() => Object.values(state.registry?.zones || {}), [state.registry]);
  const events = state.events?.events || [];
  const auditEvents = state.audit?.events || [];
  const explanations = state.explanations?.explanations || [];

  return (
    <section className="border-y border-slate-800/80 bg-[#080b14] px-6 py-24 md:py-32">
      <div className="mx-auto max-w-7xl">
        <div className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end">
          <div>
            <p className="mb-3 text-xs font-semibold uppercase tracking-[0.28em] text-sky-300">Live backend visibility</p>
            <h2 className="text-3xl font-bold tracking-tight text-white md:text-5xl">ASZ Control Evidence</h2>
            <p className="mt-4 max-w-3xl text-base leading-8 text-slate-300">
              These panels read directly from the Agent Sovereignty Zones backend. They show trust registry state, events, audit proof, and deterministic DDR explanations.
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
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Zone Registry</h3>
              <span className="text-xs text-slate-500">{state.registry?.count ?? 0} zones</span>
            </div>
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
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Cross-Zone Events</h3>
              <span className="text-xs text-slate-500">{state.events?.count ?? 0} events</span>
            </div>
            <div className="space-y-3">
              {events.length ? events.map((event) => <EventRow key={event.event_id} event={event} />) : <Empty label="No events returned" />}
            </div>
          </div>

          <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Dual-Zone Audit Chain</h3>
              <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${state.audit?.chain_verified ? statusClass("accepted") : statusClass("created")}`}>
                {state.audit?.chain_verified ? "Verified" : "Pending"}
              </span>
            </div>
            <div className="mb-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs text-slate-400">
              Latest hash: <span className="font-mono text-slate-200">{shortHash(state.audit?.latest_hash)}</span>
            </div>
            <div className="space-y-3">
              {auditEvents.length ? auditEvents.map((event) => <HashRow key={event.event_id} event={event} />) : <Empty label="No audit records returned" />}
            </div>
          </div>

          <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-5">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">DDR Explanations</h3>
              <span className="text-xs text-slate-500">{state.explanations?.count ?? 0} explanations</span>
            </div>
            <div className="space-y-3">
              {explanations.length ? explanations.map((item, index) => <ExplanationRow key={`${item.reason_code}-${index}`} item={item} />) : <Empty label="No explanations returned" />}
            </div>
          </div>
        </div>
      </div>
    </section>
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
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${statusClass(item.outcome)}`}>{item.outcome}</span>
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
      const [registry, events, audit, explanations] = await Promise.all([
        fetchJson<TrustRegistryResponse>("/v1/zones/trust-registry"),
        fetchJson<EventsResponse>("/v1/zones/events"),
        fetchJson<AuditResponse>("/v1/zones/audit"),
        fetchJson<ExplanationsResponse>("/v1/zones/explanations"),
      ]);
      setState({ registry, events, audit, explanations });
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
      <section className="relative overflow-hidden px-6 pb-24 pt-28 md:pb-32 md:pt-40">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_20%,rgba(56,189,248,0.17),transparent_35%),radial-gradient(circle_at_78%_35%,rgba(37,99,235,0.16),transparent_34%)]" />
        <div className="relative mx-auto grid max-w-7xl items-center gap-12 lg:grid-cols-[0.9fr_1.1fr]">
          <div>
            <Badge>Agent Sovereignty Zones</Badge>
            <h1 className="mt-7 text-5xl font-bold leading-[1.05] tracking-[-0.04em] text-white md:text-7xl">
              Cross-Domain Trust for Autonomous Agents
            </h1>
            <p className="mt-7 max-w-2xl text-lg leading-8 text-slate-300 md:text-xl">
              Let independent organizations run their own SecureTheCloud governance domains while safely allowing trusted AI agents to interact across boundaries through signed assertions, local re-evaluation, deterministic explanations, and dual-zone audit anchoring.
            </p>
            <div className="mt-9"><CTAButtons /></div>
            <p className="mt-6 max-w-xl text-sm leading-6 text-slate-400">
              Built on SecureTheCloud Aegis Runtime. DDR is embedded. OPA remains final. No foreign zone can authorize execution inside another zone.
            </p>
          </div>
          <StatusPanel audit={state.audit} />
                                               </div>
                                      </section>

                                     <HandshakeSimulator onComplete={loadDashboard} />

                                     <DataPanel state={state} loading={loading} error={error} onRefresh={loadDashboard} />

      <section className="border-y border-slate-800/80 bg-[#080b14] px-6 py-24 md:py-32">
        <div className="mx-auto max-w-7xl">
          <SectionHeader
            eyebrow="Why it matters"
            title="Autonomous Agents Will Cross Organizational Boundaries"
            body="Enterprises need AI agents to collaborate with vendors, partners, cloud platforms, and regulated systems. Agent Sovereignty Zones makes those interactions verifiable without requiring shared infrastructure or implicit trust."
          />
          <div className="grid gap-5 md:grid-cols-3">
            <Card icon={AlertTriangle} title="No Shared Governance" body="Every organization has different policy, risk, identity, and audit requirements." />
            <Card icon={Network} title="No Implicit Trust" body="Foreign agents can present evidence, but the receiving zone must verify independently." />
            <Card icon={Database} title="No Unprovable Actions" body="Cross-zone activity can be explained and anchored into deterministic audit history." />
          </div>
        </div>
      </section>

      <section className="px-6 py-24 md:py-32">
        <div className="mx-auto max-w-7xl">
          <SectionHeader
            eyebrow="Architecture"
            title="Each Zone Is Sovereign. Every Interaction Is Verified."
            body="A foreign zone can provide signed context, but the receiving zone owns final authority. Verified assertions are forwarded to local runtime evaluation — not treated as execution approval."
          />
          <ZoneDiagram />
        </div>
      </section>

      <section className="border-y border-slate-800/80 bg-[#080b14] px-6 py-24 md:py-32">
        <div className="mx-auto max-w-7xl">
          <SectionHeader eyebrow="Validation path" title="The Cross-Zone Handshake" />
          <div className="grid gap-4 md:grid-cols-6">
            {handshakeSteps.map((step, index) => (
              <div key={step} className="relative rounded-3xl border border-slate-700/60 bg-slate-950/60 p-5 text-center">
                <p className="mx-auto mb-3 flex h-8 w-8 items-center justify-center rounded-full bg-sky-300/10 text-sm font-bold text-sky-300">
                  {index + 1}
                </p>
                <p className="text-sm font-semibold text-white">{step}</p>
                {index < handshakeSteps.length - 1 ? <ArrowRight className="absolute -right-3 top-1/2 hidden h-5 w-5 -translate-y-1/2 text-slate-600 md:block" /> : null}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="px-6 py-24 md:py-32">
        <div className="mx-auto max-w-7xl">
          <SectionHeader
            eyebrow="Capabilities"
            title="Built on the Aegis Runtime Baseline"
            body="Agent Sovereignty Zones extends the existing runtime with protocol-level trust, not a second authorization system. The local runtime still owns final execution decisions."
          />
          <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
            {productPillars.map((pillar) => <Card key={pillar.title} {...pillar} />)}
          </div>
        </div>
      </section>

      <section className="border-y border-slate-800/80 bg-[#080b14] px-6 py-24 md:py-32">
        <div className="mx-auto max-w-7xl">
          <SectionHeader eyebrow="Use cases" title="Where Agent Sovereignty Zones Fits" />
          <div className="grid gap-4 md:grid-cols-2">
            {useCases.map((item) => (
              <div key={item} className="flex items-start gap-3 rounded-3xl border border-slate-700/50 bg-slate-900/50 p-5">
                <CheckCircle2 className="mt-1 h-5 w-5 shrink-0 text-sky-300" />
                <p className="text-sm leading-7 text-slate-200">{item}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="px-6 py-24 md:py-32">
        <div className="mx-auto max-w-5xl rounded-[2rem] border border-sky-300/20 bg-[radial-gradient(circle_at_top,rgba(56,189,248,0.18),transparent_38%),#07101d] p-8 text-center md:p-14">
          <Layers3 className="mx-auto mb-6 h-10 w-10 text-sky-300" />
          <h2 className="text-4xl font-bold tracking-tight text-white md:text-6xl">
            Build Cross-Domain Trust Before Agents Cross Boundaries
          </h2>
          <p className="mx-auto mt-6 max-w-3xl text-lg leading-8 text-slate-300">
            Request a private technical demo and see how Agent Sovereignty Zones extends SecureTheCloud Aegis Runtime into cryptographically verifiable cross-organization governance.
          </p>
          <div className="mt-9 flex justify-center"><CTAButtons /></div>
        </div>
      </section>
    </main>
  );
}
