/**
 * Coordination and context-hygiene patterns for multi-step AI agents.
 *
 * Implements Skills 1-3 in strict zero-dependency TypeScript:
 * 1. IntentRouter and ScopedToolRegistry (intent-and-tool-routing)
 * 2. SupervisorGate (supervisor-delegation-gate)
 * 3. PassByRefBlackboard (pass-by-reference-blackboard)
 */
export declare function canonicalJson(value: unknown): string;
export declare function utf8Bytes(input: string): Uint8Array;
export declare function sha256Bytes(data: Uint8Array): string;
export declare function sha256Hex(text: string): string;
export type ToolViolationReason = "intent_not_allowed" | "read_only_required";
export declare class ToolScopeViolationError extends Error {
    readonly activeIntent: string;
    readonly toolName: string;
    readonly allowedIntents: readonly string[];
    readonly reason: ToolViolationReason;
    constructor(params: {
        activeIntent: string;
        toolName: string;
        allowedIntents: readonly string[];
        reason?: ToolViolationReason;
    });
}
export interface RouteRule {
    readonly intent: string;
    readonly keywords?: readonly string[];
    readonly predicate?: (utterance: string) => boolean;
    readonly priority?: number;
}
export type MatchedBy = "rule" | "classifier" | "fallback";
export interface IntentDecision {
    readonly intent: string;
    readonly confidence: number;
    readonly matchedBy: MatchedBy;
    readonly reason: string;
}
export type ClassifierFn = (utterance: string) => {
    readonly intent: string;
    readonly confidence: number;
};
export interface IntentRouterOptions {
    readonly rules?: readonly RouteRule[];
    readonly classifier?: ClassifierFn;
    readonly minConfidence?: number;
    readonly fallbackIntent?: string;
    readonly knownIntents?: ReadonlySet<string> | readonly string[];
}
export declare class IntentRouter {
    private readonly rules;
    private readonly classifier;
    private readonly minConfidence;
    private readonly fallbackIntent;
    private readonly knownIntents;
    constructor(options?: IntentRouterOptions);
    route(utterance: string): IntentDecision;
}
export interface ToolSpec<TIn = unknown, TOut = unknown> {
    readonly name: string;
    readonly description: string;
    readonly allowedIntents: readonly string[];
    readonly readOnly?: boolean;
    readonly handler: (payload: TIn) => TOut;
}
export interface ToolManifestEntry {
    readonly name: string;
    readonly description: string;
    readonly readOnly: boolean;
}
export declare class ScopedToolRegistry {
    private readonly tools;
    register<TIn, TOut>(spec: ToolSpec<TIn, TOut>): void;
    toolsForIntent(intent: string, options?: {
        readonly readOnlyOnly?: boolean;
    }): ToolSpec<unknown, unknown>[];
    exportManifest(intent: string, options?: {
        readonly readOnlyOnly?: boolean;
    }): ToolManifestEntry[];
    invoke<TOut = unknown>(params: {
        readonly activeIntent: string;
        readonly toolName: string;
        readonly payload: unknown;
        readonly requireReadOnly?: boolean;
    }): TOut;
}
export type DenialReason = "UNKNOWN_WORKER" | "TRANSITION_FORBIDDEN" | "CYCLE_DETECTED" | "MAX_DEPTH_EXCEEDED" | "WORKER_QUOTA_EXCEEDED" | "BUDGET_EXHAUSTED";
export declare class DelegationDeniedError extends Error {
    readonly reason: DenialReason;
    readonly caller: string;
    readonly worker: string;
    readonly lineage: readonly string[];
    constructor(params: {
        reason: DenialReason;
        caller: string;
        worker: string;
        lineage: readonly string[];
        detail: string;
    });
}
export interface DelegationPolicy {
    readonly allowedTransitions: Readonly<Record<string, readonly string[]>>;
    readonly maxDepth?: number;
    readonly maxTotalDelegations?: number;
    readonly maxCallsPerWorker?: number;
    readonly preventCycles?: boolean;
}
export interface DelegationTask<TPayload = unknown> {
    readonly taskId: string;
    readonly caller: string;
    readonly worker: string;
    readonly objective: string;
    readonly payload: TPayload;
    readonly lineage?: readonly string[];
}
export interface DelegationReceipt<TResult = unknown> {
    readonly taskId: string;
    readonly caller: string;
    readonly worker: string;
    readonly depth: number;
    readonly sequenceNum: number;
    readonly lineage: readonly string[];
    readonly output: TResult;
}
export declare class SupervisorGate {
    private readonly allowedTransitions;
    private readonly maxDepth;
    private readonly maxTotalDelegations;
    private readonly maxCallsPerWorker;
    private readonly preventCycles;
    private readonly workers;
    private totalDelegations;
    private readonly workerCounts;
    private readonly recordedReceipts;
    constructor(policy: DelegationPolicy);
    registerWorker<TPayload, TResult>(name: string, handler: (task: DelegationTask<TPayload>) => TResult): void;
    get remainingBudget(): number;
    get receipts(): readonly DelegationReceipt<unknown>[];
    delegate<TPayload, TResult = unknown>(task: DelegationTask<TPayload>): DelegationReceipt<TResult>;
}
export declare class BlackboardError extends Error {
    constructor(message: string);
}
export declare class BlackboardAccessError extends BlackboardError {
    constructor(message: string);
}
export declare class BlackboardIntegrityError extends BlackboardError {
    constructor(message: string);
}
export declare class BlackboardExpiredError extends BlackboardError {
    constructor(message: string);
}
export interface ContextToken {
    readonly refId: string;
    readonly kind: string;
    readonly byteSize: number;
    readonly sha256Prefix: string;
    readonly version: number;
    readonly summary: string;
}
export interface ArtifactPointer {
    readonly refId: string;
    readonly key: string;
    readonly kind: string;
    readonly sha256: string;
    readonly byteSize: number;
    readonly summary: string;
    readonly producer: string;
    readonly version: number;
    readonly createdAtMs: number;
    readonly expiresAtMs: number | null;
    toContextToken(): ContextToken;
}
export declare class PassByRefBlackboard {
    private readonly maxSummaryChars;
    private readonly clock;
    private readonly records;
    private readonly versionsByKey;
    constructor(options?: {
        readonly maxSummaryChars?: number;
        readonly clock?: () => number;
    });
    put(params: {
        readonly key: string;
        readonly value: unknown;
        readonly kind: string;
        readonly summary: string;
        readonly producer: string;
        readonly allowedReaders?: readonly string[];
        readonly ttlMs?: number;
    }): ArtifactPointer;
    resolve<T = unknown>(refId: string, reader: string): T;
    pruneExpired(): number;
}
