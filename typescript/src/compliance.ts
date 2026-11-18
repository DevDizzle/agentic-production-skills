/**
 * Governance, policy anchoring, independent verification, and causal auditability.
 *
 * Implements Skills 4-6 in strict zero-dependency TypeScript:
 * 4. ConstraintEnvelope (constraint-anchoring)
 * 5. IndependentAuditorGate (independent-auditor-gate)
 * 6. CausalAuditLedger (causal-audit-ledger)
 */

import { canonicalJson, sha256Hex } from "./coordination.ts";

function deepFreezeJson<T>(value: T): T {
  const cloned = JSON.parse(canonicalJson(value)) as T;
  const freezeRec = (node: unknown): void => {
    if (node !== null && typeof node === "object") {
      Object.freeze(node);
      if (Array.isArray(node)) {
        for (const item of node) {
          freezeRec(item);
        }
      } else {
        for (const val of Object.values(node as Record<string, unknown>)) {
          freezeRec(val);
        }
      }
    }
  };
  freezeRec(cloned);
  return cloned;
}

// ---------------------------------------------------------------------------
// Skill 4: Constraint Anchoring
// ---------------------------------------------------------------------------

export class ConstraintTamperError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "ConstraintTamperError";
  }
}

export type InvariantSeverity = "CRITICAL" | "HIGH" | "MEDIUM";

export interface InvariantValidationOutcome {
  readonly passed: boolean;
  readonly detail: string;
}

export interface Invariant<TContext = Readonly<Record<string, unknown>>> {
  readonly ruleId: string;
  readonly statement: string;
  readonly severity: InvariantSeverity;
  readonly validator: (context: TContext) => InvariantValidationOutcome;
}

export interface ConstraintViolation {
  readonly ruleId: string;
  readonly severity: InvariantSeverity;
  readonly statement: string;
  readonly detail: string;
}

export interface ConstraintCheckResult {
  readonly allowed: boolean;
  readonly envelopeId: string;
  readonly fingerprint: string;
  readonly violations: readonly ConstraintViolation[];
}

export class ConstraintEnvelope<
  TContext = Readonly<Record<string, unknown>>,
> {
  public readonly envelopeId: string;
  public readonly invariants: readonly Invariant<TContext>[];
  public readonly fingerprint: string;

  public constructor(params: {
    readonly envelopeId: string;
    readonly invariants: readonly Invariant<TContext>[];
  }) {
    if (params.envelopeId.trim().length === 0) {
      throw new Error("envelopeId must be non-empty");
    }
    if (params.invariants.length === 0) {
      throw new Error("ConstraintEnvelope requires at least one Invariant");
    }
    const cloned = params.invariants.map((inv) =>
      Object.freeze({
        ruleId: inv.ruleId,
        statement: inv.statement,
        severity: inv.severity,
        validator: inv.validator,
      }),
    );
    cloned.sort((a, b) => (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0));
    const seen = new Set<string>();
    for (const inv of cloned) {
      if (seen.has(inv.ruleId)) {
        throw new Error(`Duplicate invariant ruleId: '${inv.ruleId}'`);
      }
      seen.add(inv.ruleId);
    }
    this.envelopeId = params.envelopeId;
    this.invariants = Object.freeze(cloned);
    this.fingerprint = this.computeFingerprint();
  }

  private computeFingerprint(): string {
    const canonicalSpec = this.invariants.map((inv) => ({
      rule_id: inv.ruleId,
      severity: inv.severity,
      statement: inv.statement,
    }));
    return sha256Hex(
      canonicalJson({
        envelope_id: this.envelopeId,
        rules: canonicalSpec,
      }),
    );
  }

  public verifyFingerprint(expectedFingerprint: string): void {
    const live = this.computeFingerprint();
    if (
      live !== expectedFingerprint ||
      this.fingerprint !== expectedFingerprint
    ) {
      throw new ConstraintTamperError(
        `Constraint envelope '${this.envelopeId}' fingerprint mismatch: expected ${expectedFingerprint}, computed ${live}`,
      );
    }
  }

  public static shouldReanchor(params: {
    readonly turnIndex: number;
    readonly everyNTurns?: number;
    readonly compacted?: boolean;
  }): boolean {
    const everyN = params.everyNTurns ?? 4;
    if (!Number.isInteger(everyN) || everyN < 1) {
      throw new RangeError("everyNTurns must be an integer >= 1");
    }
    if (params.compacted) {
      return true;
    }
    return params.turnIndex > 0 && params.turnIndex % everyN === 0;
  }

  public renderAnchorBlock(turnIndex: number): string {
    const lines: string[] = [
      `[ANCHORED_CONSTRAINTS id=${this.envelopeId} sha256=${this.fingerprint.slice(0, 16)} turn=${turnIndex}]`,
    ];
    for (const inv of this.invariants) {
      lines.push(`- [${inv.severity}] (${inv.ruleId}) ${inv.statement}`);
    }
    lines.push("[/ANCHORED_CONSTRAINTS]");
    return lines.join("\n");
  }

  public evaluateAction(
    actionContext: TContext,
    expectedFingerprint?: string,
  ): ConstraintCheckResult {
    if (expectedFingerprint !== undefined) {
      this.verifyFingerprint(expectedFingerprint);
    }
    const violations: ConstraintViolation[] = [];
    for (const inv of this.invariants) {
      const outcome = inv.validator(actionContext);
      if (!outcome.passed) {
        violations.push({
          ruleId: inv.ruleId,
          severity: inv.severity,
          statement: inv.statement,
          detail: outcome.detail,
        });
      }
    }
    return {
      allowed: violations.length === 0,
      envelopeId: this.envelopeId,
      fingerprint: this.fingerprint,
      violations,
    };
  }
}

// ---------------------------------------------------------------------------
// Skill 5: Independent Auditor Gate
// ---------------------------------------------------------------------------

const REASONING_CLOSED_RE =
  /<(think|thought|scratchpad|reasoning|internal_monologue)(?:\s[^>]*)?>[\s\S]*?<\/\1\s*>/gi;

const REASONING_UNCLOSED_RE =
  /<(think|thought|scratchpad|reasoning|internal_monologue)(?:\s[^>]*)?>[\s\S]*$/i;

export function stripReasoningTrace(rawOutput: string): string {
  let cleaned = rawOutput;
  while (true) {
    REASONING_CLOSED_RE.lastIndex = 0;
    const nextCleaned = cleaned.replace(REASONING_CLOSED_RE, "");
    if (nextCleaned === cleaned) {
      break;
    }
    cleaned = nextCleaned;
  }
  cleaned = cleaned.replace(REASONING_UNCLOSED_RE, "");
  return cleaned.trim();
}

export interface AuditCriterion {
  readonly criterionId: string;
  readonly description: string;
  readonly deterministicCheck?: (
    candidateOutput: string,
    evidence: Readonly<Record<string, unknown>>,
  ) => { readonly passed: boolean; readonly detail: string };
}

export interface AuditPacket {
  readonly specification: string;
  readonly candidateOutput: string;
  readonly criteria: readonly {
    readonly criterionId: string;
    readonly description: string;
  }[];
  readonly evidence: Readonly<Record<string, unknown>>;
}

export interface AuditVerdict {
  readonly approved: boolean;
  readonly auditorId: string;
  readonly failedCriteria: readonly string[];
  readonly findings: readonly string[];
  readonly remediation: string;
}

export interface GuardedGenerationResult {
  readonly approved: boolean;
  readonly finalOutput: string;
  readonly revisionsUsed: number;
  readonly verdicts: readonly AuditVerdict[];
}

export interface NamedAuditor {
  readonly auditorId: string;
  readonly evaluate: (packet: AuditPacket) => AuditVerdict;
}

export class IndependentAuditorGate {
  private readonly criteria: readonly AuditCriterion[];
  private readonly auditors: readonly NamedAuditor[];

  public constructor(params: {
    readonly criteria: readonly AuditCriterion[];
    readonly auditors?: readonly NamedAuditor[];
  }) {
    if (params.criteria.length === 0) {
      throw new Error("At least one AuditCriterion is required");
    }
    this.criteria = [...params.criteria];
    this.auditors = [...(params.auditors ?? [])];
  }

  public evaluate(params: {
    readonly specification: string;
    readonly rawCandidateOutput: string;
    readonly evidence?: Readonly<Record<string, unknown>>;
  }): AuditVerdict {
    const evidence: Readonly<Record<string, unknown>> = params.evidence
      ? deepFreezeJson(params.evidence)
      : Object.freeze({});
    const isolatedOutput = stripReasoningTrace(params.rawCandidateOutput);

    const detFailedIds: string[] = [];
    const detFindings: string[] = [];

    for (const crit of this.criteria) {
      if (crit.deterministicCheck) {
        const res = crit.deterministicCheck(isolatedOutput, evidence);
        if (!res.passed) {
          detFailedIds.push(crit.criterionId);
          detFindings.push(`[${crit.criterionId}] ${res.detail}`);
        }
      }
    }

    if (detFailedIds.length > 0) {
      return {
        approved: false,
        auditorId: "deterministic_precheck",
        failedCriteria: detFailedIds,
        findings: detFindings,
        remediation: `Resolve deterministic rubric failures: ${detFindings.join("; ")}`,
      };
    }

    const packet: AuditPacket = Object.freeze({
      specification: params.specification,
      candidateOutput: isolatedOutput,
      criteria: Object.freeze(
        this.criteria.map((c) =>
          Object.freeze({
            criterionId: c.criterionId,
            description: c.description,
          }),
        ),
      ),
      evidence,
    });

    const failedIds: string[] = [];
    const findings: string[] = [];
    const remediations: string[] = [];
    const auditorLabels: string[] = [];
    let anyRejected = false;

    for (const auditor of this.auditors) {
      auditorLabels.push(auditor.auditorId);
      const verdict = auditor.evaluate(packet);
      if (!verdict.approved) {
        anyRejected = true;
      }
      if (
        !verdict.approved ||
        verdict.failedCriteria.length > 0 ||
        verdict.findings.length > 0
      ) {
        for (const cid of verdict.failedCriteria) {
          if (!failedIds.includes(cid)) {
            failedIds.push(cid);
          }
        }
        for (const f of verdict.findings) {
          findings.push(`[${auditor.auditorId}] ${f}`);
        }
        if (verdict.remediation.length > 0) {
          remediations.push(verdict.remediation);
        }
      }
    }

    const approved =
      !anyRejected && failedIds.length === 0 && findings.length === 0;
    return {
      approved,
      auditorId:
        auditorLabels.length > 0
          ? auditorLabels.join("+")
          : "deterministic_only",
      failedCriteria: failedIds,
      findings,
      remediation: remediations.join(" | "),
    };
  }

  public runGuardedLoop(params: {
    readonly specification: string;
    readonly generator: (
      specification: string,
      priorVerdicts: readonly AuditVerdict[],
    ) => string;
    readonly evidence?: Readonly<Record<string, unknown>>;
    readonly maxRevisions?: number;
  }): GuardedGenerationResult {
    const maxRevisions = params.maxRevisions ?? 2;
    if (!Number.isInteger(maxRevisions) || maxRevisions < 0) {
      throw new RangeError("maxRevisions must be an integer >= 0");
    }

    const verdicts: AuditVerdict[] = [];
    let latestClean = "";

    for (let attempt = 0; attempt <= maxRevisions; attempt++) {
      const rawCandidate = params.generator(params.specification, [
        ...verdicts,
      ]);
      latestClean = stripReasoningTrace(rawCandidate);
      const verdict = this.evaluate({
        specification: params.specification,
        rawCandidateOutput: rawCandidate,
        evidence: params.evidence,
      });
      verdicts.push(verdict);
      if (verdict.approved) {
        return {
          approved: true,
          finalOutput: latestClean,
          revisionsUsed: attempt,
          verdicts,
        };
      }
    }

    return {
      approved: false,
      finalOutput: latestClean,
      revisionsUsed: maxRevisions,
      verdicts,
    };
  }
}

// ---------------------------------------------------------------------------
// Skill 6: Causal Audit Ledger
// ---------------------------------------------------------------------------

export class LedgerIntegrityError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "LedgerIntegrityError";
  }
}

export interface LedgerEntry {
  readonly seq: number;
  readonly entryId: string;
  readonly timestampMs: number;
  readonly actor: string;
  readonly eventType: string;
  readonly parentIds: readonly string[];
  readonly payloadDigest: string;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly prevHash: string;
  readonly entryHash: string;
}

export interface ChainVerificationResult {
  readonly valid: boolean;
  readonly checkedEntries: number;
  readonly error: string | null;
  readonly brokenAtSeq: number | null;
}

export class CausalAuditLedger {
  public static readonly GENESIS_HASH = "0".repeat(64);
  private readonly clock: () => number;
  private readonly ledgerEntries: LedgerEntry[] = [];
  private readonly indexById = new Map<string, number>();

  public constructor(options: { readonly clock?: () => number } = {}) {
    this.clock = options.clock ?? (() => Date.now());
  }

  public get entries(): readonly LedgerEntry[] {
    return [...this.ledgerEntries];
  }

  private static computeEntryHash(params: {
    readonly seq: number;
    readonly entryId: string;
    readonly timestampMs: number;
    readonly actor: string;
    readonly eventType: string;
    readonly parentIds: readonly string[];
    readonly payloadDigest: string;
    readonly metadata: Readonly<Record<string, unknown>>;
    readonly prevHash: string;
  }): string {
    return sha256Hex(
      canonicalJson({
        actor: params.actor,
        entry_id: params.entryId,
        event_type: params.eventType,
        metadata: params.metadata,
        parent_ids: params.parentIds,
        payload_digest: params.payloadDigest,
        prev_hash: params.prevHash,
        seq: params.seq,
        timestamp_ms: params.timestampMs,
      }),
    );
  }

  public append(params: {
    readonly actor: string;
    readonly eventType: string;
    readonly payload: unknown;
    readonly parentIds?: readonly string[];
    readonly metadata?: Readonly<Record<string, unknown>>;
    readonly entryId?: string;
  }): LedgerEntry {
    const seq = this.ledgerEntries.length;
    const resolvedId = params.entryId ?? `evt-${String(seq).padStart(6, "0")}`;

    if (this.indexById.has(resolvedId)) {
      throw new LedgerIntegrityError(`Duplicate entryId: '${resolvedId}'`);
    }

    const dedupParents = Object.freeze([...new Set(params.parentIds ?? [])]);
    for (const pid of dedupParents) {
      if (!this.indexById.has(pid)) {
        throw new LedgerIntegrityError(
          `Unknown causal parentId '${pid}' referenced by '${resolvedId}'`,
        );
      }
    }

    const lastEntry = this.ledgerEntries[this.ledgerEntries.length - 1];
    const prevHash = lastEntry
      ? lastEntry.entryHash
      : CausalAuditLedger.GENESIS_HASH;
    const payloadDigest = sha256Hex(canonicalJson(params.payload));
    const frozenMetadata: Readonly<Record<string, unknown>> = params.metadata
      ? deepFreezeJson(params.metadata)
      : Object.freeze({});
    const timestampMs = this.clock();

    const entryHash = CausalAuditLedger.computeEntryHash({
      seq,
      entryId: resolvedId,
      timestampMs,
      actor: params.actor,
      eventType: params.eventType,
      parentIds: dedupParents,
      payloadDigest,
      metadata: frozenMetadata,
      prevHash,
    });

    const entry: LedgerEntry = Object.freeze({
      seq,
      entryId: resolvedId,
      timestampMs,
      actor: params.actor,
      eventType: params.eventType,
      parentIds: dedupParents,
      payloadDigest,
      metadata: frozenMetadata,
      prevHash,
      entryHash,
    });

    this.ledgerEntries.push(entry);
    this.indexById.set(resolvedId, seq);
    return entry;
  }

  public verifyPayload(entryId: string, candidatePayload: unknown): boolean {
    const idx = this.indexById.get(entryId);
    if (idx === undefined) {
      throw new Error(`Unknown entryId: '${entryId}'`);
    }
    const entry = this.ledgerEntries[idx];
    if (!entry) {
      throw new Error(`Missing ledger entry at seq=${idx}`);
    }
    return entry.payloadDigest === sha256Hex(canonicalJson(candidatePayload));
  }

  public verifyChain(): ChainVerificationResult {
    let expectedPrev = CausalAuditLedger.GENESIS_HASH;
    const seenIds = new Map<string, number>();

    for (let idx = 0; idx < this.ledgerEntries.length; idx++) {
      const entry = this.ledgerEntries[idx];
      if (!entry || entry.seq !== idx) {
        return {
          valid: false,
          checkedEntries: idx,
          error: `Sequence gap at index ${idx}`,
          brokenAtSeq: idx,
        };
      }
      if (entry.prevHash !== expectedPrev) {
        return {
          valid: false,
          checkedEntries: idx,
          error: `prevHash mismatch at seq=${idx}`,
          brokenAtSeq: idx,
        };
      }
      for (const pid of entry.parentIds) {
        const parentSeq = seenIds.get(pid);
        if (parentSeq === undefined || parentSeq >= idx) {
          return {
            valid: false,
            checkedEntries: idx,
            error: `Invalid causal parent '${pid}' at seq=${idx}`,
            brokenAtSeq: idx,
          };
        }
      }
      const recomputed = CausalAuditLedger.computeEntryHash({
        seq: entry.seq,
        entryId: entry.entryId,
        timestampMs: entry.timestampMs,
        actor: entry.actor,
        eventType: entry.eventType,
        parentIds: entry.parentIds,
        payloadDigest: entry.payloadDigest,
        metadata: entry.metadata,
        prevHash: entry.prevHash,
      });
      if (recomputed !== entry.entryHash) {
        return {
          valid: false,
          checkedEntries: idx,
          error: `entryHash mismatch at seq=${idx}`,
          brokenAtSeq: idx,
        };
      }
      seenIds.set(entry.entryId, idx);
      expectedPrev = entry.entryHash;
    }

    return {
      valid: true,
      checkedEntries: this.ledgerEntries.length,
      error: null,
      brokenAtSeq: null,
    };
  }

  public traceAncestors(entryId: string): LedgerEntry[] {
    const targetSeq = this.indexById.get(entryId);
    if (targetSeq === undefined) {
      throw new Error(`Unknown entryId: '${entryId}'`);
    }
    const target = this.ledgerEntries[targetSeq];
    if (!target) {
      return [];
    }

    const visited = new Set<string>();
    const queue: string[] = [...target.parentIds];

    while (queue.length > 0) {
      const pid = queue.shift();
      if (pid === undefined || visited.has(pid)) {
        continue;
      }
      visited.add(pid);
      const pIdx = this.indexById.get(pid);
      const parentEntry =
        pIdx !== undefined ? this.ledgerEntries[pIdx] : undefined;
      if (parentEntry) {
        for (const grandPid of parentEntry.parentIds) {
          if (!visited.has(grandPid)) {
            queue.push(grandPid);
          }
        }
      }
    }

    const ancestors: LedgerEntry[] = [];
    for (const eid of visited) {
      const idx = this.indexById.get(eid);
      const item = idx !== undefined ? this.ledgerEntries[idx] : undefined;
      if (item) {
        ancestors.push(item);
      }
    }
    ancestors.sort((a, b) => a.seq - b.seq);
    return ancestors;
  }
}
