/**
 * Resilience, consensus, escalation, prompt-injection firewall, and rollout gates.
 *
 * Implements Skills 7-12 in strict zero-dependency TypeScript:
 * 7. IdempotentCheckpointer (idempotent-checkpointing)
 * 8. WatchdogRetryRunner (watchdog-adaptive-retry)
 * 9. ParallelConsensus (parallel-consensus-voting)
 * 10. TieredEscalationGate (tiered-human-escalation)
 * 11. UntrustedInputFirewall (untrusted-input-firewall)
 * 12. ShadowCanaryRunner (shadow-canary-eval)
 */
export interface AbortSignalLike {
    readonly aborted: boolean;
    readonly reason?: unknown;
    addEventListener?(type: "abort", listener: () => void, options?: {
        readonly once?: boolean;
    }): void;
    removeEventListener?(type: "abort", listener: () => void): void;
}
export declare class DuplicateInFlightError extends Error {
    constructor(message: string);
}
export type StepStatus = "PENDING" | "COMPLETED" | "FAILED";
export interface StepRecord<TOut = unknown> {
    readonly idempotencyKey: string;
    readonly workflowId: string;
    readonly stepName: string;
    readonly status: StepStatus;
    readonly attempts: number;
    readonly output: TOut | null;
    readonly lastError: string | null;
    readonly updatedAtMs: number;
}
export interface IdempotentExecutionResult<TOut> {
    readonly idempotencyKey: string;
    readonly output: TOut;
    readonly replayed: boolean;
    readonly attempts: number;
}
export interface CheckpointSnapshot {
    readonly workflowId: string;
    readonly cursor: string;
    readonly state: Readonly<Record<string, unknown>>;
    readonly completedKeys: readonly string[];
    readonly savedAtMs: number;
}
export declare class IdempotentCheckpointer {
    private readonly clock;
    private readonly steps;
    private readonly checkpoints;
    constructor(options?: {
        readonly clock?: () => number;
    });
    static deriveKey(workflowId: string, stepName: string, args: Readonly<Record<string, unknown>>): string;
    getStep(idempotencyKey: string): StepRecord<unknown> | undefined;
    private beginStep;
    executeOnce<TOut>(params: {
        readonly workflowId: string;
        readonly stepName: string;
        readonly args: Readonly<Record<string, unknown>>;
        readonly action: () => TOut;
    }): IdempotentExecutionResult<TOut>;
    executeOnceAsync<TOut>(params: {
        readonly workflowId: string;
        readonly stepName: string;
        readonly args: Readonly<Record<string, unknown>>;
        readonly action: () => Promise<TOut> | TOut;
    }): Promise<IdempotentExecutionResult<TOut>>;
    saveCheckpoint(params: {
        readonly workflowId: string;
        readonly cursor: string;
        readonly state: Readonly<Record<string, unknown>>;
    }): CheckpointSnapshot;
    loadCheckpoint(workflowId: string): CheckpointSnapshot | null;
}
export type FailureClass = "TRANSIENT" | "VALIDATION" | "TIMEOUT" | "TERMINAL";
export declare class CircuitOpenError extends Error {
    constructor(message: string);
}
export declare class ClassifiedError extends Error {
    readonly failureClass: FailureClass;
    constructor(failureClass: FailureClass, message: string);
}
export interface RetryPolicy {
    readonly maxAttempts?: number;
    readonly timeoutMs?: number;
    readonly baseBackoffMs?: number;
    readonly maxBackoffMs?: number;
    readonly circuitFailureThreshold?: number;
    readonly circuitCooldownMs?: number;
    readonly abortOnRepeatedSignature?: boolean;
}
export interface AttemptRecord {
    readonly attempt: number;
    readonly elapsedMs: number;
    readonly succeeded: boolean;
    readonly failureClass: FailureClass | null;
    readonly errorMessage: string | null;
    readonly nextBackoffMs: number;
    readonly repairedInputApplied: boolean;
}
export interface RetryOutcome<TOut> {
    readonly succeeded: boolean;
    readonly value: TOut | null;
    readonly attempts: readonly AttemptRecord[];
    readonly abortedReason: string | null;
}
export declare class WatchdogRetryRunner {
    private readonly maxAttempts;
    private readonly timeoutMs;
    private readonly baseBackoffMs;
    private readonly maxBackoffMs;
    private readonly circuitFailureThreshold;
    private readonly circuitCooldownMs;
    private readonly abortOnRepeatedSignature;
    private readonly classifier;
    private readonly clock;
    private readonly sleeper;
    private readonly asyncSleeper;
    private consecutiveFailures;
    private circuitOpenUntilMs;
    constructor(options?: {
        readonly policy?: RetryPolicy;
        readonly classifier?: (err: unknown) => FailureClass;
        readonly clock?: () => number;
        readonly sleeper?: (backoffMs: number) => void;
        readonly asyncSleeper?: (backoffMs: number) => Promise<void>;
    });
    get isCircuitOpen(): boolean;
    private checkCircuit;
    private recordFailure;
    private recordSuccess;
    run<TIn, TOut>(params: {
        readonly initialInput: TIn;
        readonly operation: (input: TIn, attempt: number) => TOut;
        readonly repair?: (previousInput: TIn, errorMessage: string, attempt: number) => TIn;
    }): RetryOutcome<TOut>;
    private runAttemptWithDeadline;
    runAsync<TIn, TOut>(params: {
        readonly initialInput: TIn;
        readonly operation: (input: TIn, attempt: number, signal: AbortSignalLike) => Promise<TOut> | TOut;
        readonly repair?: (previousInput: TIn, errorMessage: string, attempt: number) => Promise<TIn> | TIn;
    }): Promise<RetryOutcome<TOut>>;
}
export interface Ballot<TValue> {
    readonly voterId: string;
    readonly value: TValue;
    readonly confidence?: number;
    readonly rationale?: string;
}
export interface VoterSpec<TIn, TValue> {
    readonly voterId: string;
    readonly weight?: number;
    readonly fn: (input: TIn) => Ballot<TValue>;
}
export interface AsyncVoterSpec<TIn, TValue> {
    readonly voterId: string;
    readonly weight?: number;
    readonly fn: (input: TIn) => Promise<Ballot<TValue>> | Ballot<TValue>;
}
export interface ConsensusConfig {
    readonly quorumRatio?: number;
    readonly minValidBallots?: number;
    readonly weightByConfidence?: boolean;
}
export interface ConsensusResult<TValue> {
    readonly reached: boolean;
    readonly winner: TValue | null;
    readonly winnerKey: string | null;
    readonly supportRatio: number;
    readonly tally: Readonly<Record<string, number>>;
    readonly validBallots: readonly Ballot<TValue>[];
    readonly failedVoters: readonly string[];
    readonly resolvedByArbiter: boolean;
    readonly reason: string;
}
export declare class ParallelConsensus {
    private readonly quorumRatio;
    private readonly minValidBallots;
    private readonly weightByConfidence;
    constructor(config?: ConsensusConfig);
    private static validateSpecs;
    private tallyPairedBallots;
    decide<TIn, TValue>(params: {
        readonly promptInput: TIn;
        readonly voters: readonly VoterSpec<TIn, TValue>[];
        readonly keyFn: (value: TValue) => string;
        readonly arbiter?: (input: TIn, ballots: readonly Ballot<TValue>[]) => TValue;
    }): ConsensusResult<TValue>;
    decideAsync<TIn, TValue>(params: {
        readonly promptInput: TIn;
        readonly voters: readonly AsyncVoterSpec<TIn, TValue>[];
        readonly keyFn: (value: TValue) => string;
        readonly arbiter?: (input: TIn, ballots: readonly Ballot<TValue>[]) => Promise<TValue> | TValue;
    }): Promise<ConsensusResult<TValue>>;
}
export type RiskTier = "AUTO_EXECUTE" | "ASYNC_AUDIT" | "EXPLICIT_APPROVAL" | "DUAL_CONTROL_BLOCK";
export type Reversibility = "REVERSIBLE" | "PARTIAL" | "IRREVERSIBLE";
export declare class EscalationError extends Error {
    constructor(message: string);
}
export interface ActionProposal {
    readonly proposalId: string;
    readonly proposer: string;
    readonly actionName: string;
    readonly reversibility: Reversibility;
    readonly monetaryImpact?: number;
    readonly affectedRecords?: number;
    readonly confidence?: number;
    readonly containsSensitiveData?: boolean;
}
export interface EscalationPolicy {
    readonly autoMaxMonetary?: number;
    readonly asyncAuditMaxMonetary?: number;
    readonly dualControlMonetary?: number;
    readonly bulkRecordThreshold?: number;
    readonly minAutoConfidence?: number;
    readonly ticketTtlMs?: number;
}
export interface ApprovalTicket {
    readonly ticketId: string;
    readonly proposal: ActionProposal;
    readonly tier: RiskTier;
    readonly requiredApprovals: number;
    readonly approvers: readonly string[];
    readonly rejectedBy: string | null;
    readonly createdAtMs: number;
    readonly expiresAtMs: number;
}
export interface EscalationDecision {
    readonly tier: RiskTier;
    readonly canExecuteNow: boolean;
    readonly reasons: readonly string[];
    readonly ticket: ApprovalTicket | null;
}
export declare class TieredEscalationGate {
    private readonly autoMaxMonetary;
    private readonly asyncAuditMaxMonetary;
    private readonly dualControlMonetary;
    private readonly bulkRecordThreshold;
    private readonly minAutoConfidence;
    private readonly ticketTtlMs;
    private readonly clock;
    private readonly tickets;
    private readonly auditQueue;
    constructor(options?: {
        readonly policy?: EscalationPolicy;
        readonly clock?: () => number;
    });
    get asyncAuditQueue(): readonly ActionProposal[];
    evaluate(proposal: ActionProposal): EscalationDecision;
    private createTicket;
    approve(ticketId: string, approver: string): ApprovalTicket;
    reject(ticketId: string, reviewer: string): ApprovalTicket;
    isExecutable(ticketId: string): boolean;
}
export declare class PrivilegeViolationError extends Error {
    constructor(message: string);
}
export interface FirewallFinding {
    readonly ruleId: string;
    readonly severity: number;
    readonly description: string;
}
export interface TaintedContent {
    readonly source: string;
    readonly tainted: boolean;
    readonly quarantined: boolean;
    readonly riskScore: number;
    readonly boundaryTag: string;
    readonly sanitizedText: string;
    readonly spotlightedText: string;
    readonly findings: readonly FirewallFinding[];
}
export declare class UntrustedInputFirewall {
    private readonly quarantineThreshold;
    private readonly privilegedTools;
    private readonly nonceFactory;
    constructor(options?: {
        readonly quarantineThreshold?: number;
        readonly privilegedTools?: readonly string[];
        readonly nonceFactory?: () => string;
    });
    inspectAndSpotlight(rawText: string, source: string): TaintedContent;
    assertToolAllowed(params: {
        readonly toolName: string;
        readonly contextTainted: boolean;
        readonly explicitHumanOverride?: boolean;
    }): void;
}
export type RolloutMode = "SHADOW" | "CANARY";
export type PromotionDecision = "PROMOTE" | "HOLD_COLLECT_MORE" | "ROLLBACK";
export interface PromotionPolicy {
    readonly minSamples?: number;
    readonly maxCandidateErrorRate?: number;
    readonly minMeanQualityScore?: number;
    readonly maxP95LatencyRatio?: number;
    readonly canaryBps?: number;
    readonly minSamplesBeforeRollback?: number;
}
export interface ComparisonSample {
    readonly requestId: string;
    readonly mode: RolloutMode;
    readonly servedVariant: "baseline" | "candidate";
    readonly baselineLatencyMs: number | null;
    readonly candidateLatencyMs: number | null;
    readonly candidateErrored: boolean;
    readonly qualityScore: number | null;
}
export interface RolloutExecutionResult<TOut> {
    readonly servedVariant: "baseline" | "candidate";
    readonly response: TOut;
    readonly sample: ComparisonSample;
}
export interface PromotionReport {
    readonly decision: PromotionDecision;
    readonly sampleCount: number;
    readonly candidateErrorRate: number;
    readonly meanQualityScore: number;
    readonly p95LatencyRatio: number;
    readonly autoRolledBack: boolean;
    readonly reasons: readonly string[];
}
export declare class ShadowCanaryRunner<TIn, TOut> {
    private readonly mode;
    private readonly baseline;
    private readonly candidate;
    private readonly scorer;
    private readonly minSamples;
    private readonly maxCandidateErrorRate;
    private readonly minMeanQualityScore;
    private readonly maxP95LatencyRatio;
    private readonly canaryBps;
    private readonly minSamplesBeforeRollback;
    private readonly clock;
    private readonly collectedSamples;
    private rolledBack;
    constructor(params: {
        readonly mode: RolloutMode;
        readonly baseline: (input: TIn) => TOut | Promise<TOut>;
        readonly candidate: (input: TIn) => TOut | Promise<TOut>;
        readonly scorer: (input: TIn, baselineOutput: TOut | null, candidateOutput: TOut) => number | Promise<number>;
        readonly policy?: PromotionPolicy;
        readonly clock?: () => number;
    });
    get autoRolledBack(): boolean;
    get samples(): readonly ComparisonSample[];
    private static bucketBps;
    private static validateScore;
    execute(params: {
        readonly requestId: string;
        readonly requestInput: TIn;
    }): RolloutExecutionResult<TOut>;
    executeAsync(params: {
        readonly requestId: string;
        readonly requestInput: TIn;
        readonly asyncBaseline?: (input: TIn) => Promise<TOut> | TOut;
        readonly asyncCandidate?: (input: TIn) => Promise<TOut> | TOut;
        readonly asyncScorer?: (input: TIn, baselineOutput: TOut | null, candidateOutput: TOut) => Promise<number> | number;
    }): Promise<RolloutExecutionResult<TOut>>;
    private executeShadow;
    private executeShadowAsync;
    private executeCanary;
    private executeCanaryAsync;
    private recordSample;
    evaluatePromotion(): PromotionReport;
}
