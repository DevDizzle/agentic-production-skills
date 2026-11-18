/**
 * Governance, policy anchoring, independent verification, and causal auditability.
 *
 * Implements Skills 4-6 in strict zero-dependency TypeScript:
 * 4. ConstraintEnvelope (constraint-anchoring)
 * 5. IndependentAuditorGate (independent-auditor-gate)
 * 6. CausalAuditLedger (causal-audit-ledger)
 */
export declare class ConstraintTamperError extends Error {
    constructor(message: string);
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
export declare class ConstraintEnvelope<TContext = Readonly<Record<string, unknown>>> {
    readonly envelopeId: string;
    readonly invariants: readonly Invariant<TContext>[];
    readonly fingerprint: string;
    constructor(params: {
        readonly envelopeId: string;
        readonly invariants: readonly Invariant<TContext>[];
    });
    private computeFingerprint;
    verifyFingerprint(expectedFingerprint: string): void;
    static shouldReanchor(params: {
        readonly turnIndex: number;
        readonly everyNTurns?: number;
        readonly compacted?: boolean;
    }): boolean;
    renderAnchorBlock(turnIndex: number): string;
    evaluateAction(actionContext: TContext, expectedFingerprint?: string): ConstraintCheckResult;
}
export declare function stripReasoningTrace(rawOutput: string): string;
export interface AuditCriterion {
    readonly criterionId: string;
    readonly description: string;
    readonly deterministicCheck?: (candidateOutput: string, evidence: Readonly<Record<string, unknown>>) => {
        readonly passed: boolean;
        readonly detail: string;
    };
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
export declare class IndependentAuditorGate {
    private readonly criteria;
    private readonly auditors;
    constructor(params: {
        readonly criteria: readonly AuditCriterion[];
        readonly auditors?: readonly NamedAuditor[];
    });
    evaluate(params: {
        readonly specification: string;
        readonly rawCandidateOutput: string;
        readonly evidence?: Readonly<Record<string, unknown>>;
    }): AuditVerdict;
    runGuardedLoop(params: {
        readonly specification: string;
        readonly generator: (specification: string, priorVerdicts: readonly AuditVerdict[]) => string;
        readonly evidence?: Readonly<Record<string, unknown>>;
        readonly maxRevisions?: number;
    }): GuardedGenerationResult;
}
export declare class LedgerIntegrityError extends Error {
    constructor(message: string);
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
export declare class CausalAuditLedger {
    static readonly GENESIS_HASH: string;
    private readonly clock;
    private readonly ledgerEntries;
    private readonly indexById;
    constructor(options?: {
        readonly clock?: () => number;
    });
    get entries(): readonly LedgerEntry[];
    private static computeEntryHash;
    append(params: {
        readonly actor: string;
        readonly eventType: string;
        readonly payload: unknown;
        readonly parentIds?: readonly string[];
        readonly metadata?: Readonly<Record<string, unknown>>;
        readonly entryId?: string;
    }): LedgerEntry;
    verifyPayload(entryId: string, candidatePayload: unknown): boolean;
    verifyChain(): ChainVerificationResult;
    traceAncestors(entryId: string): LedgerEntry[];
}
