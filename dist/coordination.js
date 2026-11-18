/**
 * Coordination and context-hygiene patterns for multi-step AI agents.
 *
 * Implements Skills 1-3 in strict zero-dependency TypeScript:
 * 1. IntentRouter and ScopedToolRegistry (intent-and-tool-routing)
 * 2. SupervisorGate (supervisor-delegation-gate)
 * 3. PassByRefBlackboard (pass-by-reference-blackboard)
 */
// ---------------------------------------------------------------------------
// Deterministic Canonical JSON and Pure ES2023 FIPS 180-4 SHA-256
// ---------------------------------------------------------------------------
export function canonicalJson(value) {
    if (value === null) {
        return "null";
    }
    if (typeof value === "boolean") {
        return value ? "true" : "false";
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value)) {
            throw new RangeError("Non-finite number (NaN or Infinity) is not permitted in canonical JSON");
        }
        return Object.is(value, -0) ? "0" : JSON.stringify(value);
    }
    if (typeof value === "string") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        const items = value.map((item) => {
            if (item === undefined) {
                throw new TypeError("Undefined array element is not permitted in canonical JSON");
            }
            return canonicalJson(item);
        });
        return "[" + items.join(",") + "]";
    }
    if (typeof value === "object") {
        const proto = Object.getPrototypeOf(value);
        if (proto !== null && proto !== Object.prototype) {
            throw new TypeError("Non-plain object (such as Date, Map, Set, or class instance) is not permitted in canonical JSON");
        }
        const record = value;
        const keys = Object.keys(record).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
        const parts = [];
        for (const key of keys) {
            const prop = record[key];
            if (prop === undefined) {
                throw new TypeError(`Undefined object property '${key}' is not permitted in canonical JSON`);
            }
            parts.push(`${JSON.stringify(key)}:${canonicalJson(prop)}`);
        }
        return "{" + parts.join(",") + "}";
    }
    throw new TypeError(`Unsupported type '${typeof value}' is not permitted in canonical JSON`);
}
export function utf8Bytes(input) {
    const bytes = [];
    for (let i = 0; i < input.length; i++) {
        let code = input.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff && i + 1 < input.length) {
            const next = input.charCodeAt(i + 1);
            if (next >= 0xdc00 && next <= 0xdfff) {
                code = ((code - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
                i++;
            }
        }
        if (code < 0x80) {
            bytes.push(code);
        }
        else if (code < 0x800) {
            bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        }
        else if (code < 0x10000) {
            bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
        else {
            bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
    }
    return new Uint8Array(bytes);
}
const SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
function rotr(value, shift) {
    return (value >>> shift) | (value << (32 - shift));
}
export function sha256Bytes(data) {
    const bitLen = data.length * 8;
    const totalLen = ((data.length + 9 + 63) >> 6) << 6;
    const padded = new Uint8Array(totalLen);
    padded.set(data);
    padded[data.length] = 0x80;
    const view = new DataView(padded.buffer);
    const highBits = Math.floor(bitLen / 0x100000000);
    const lowBits = bitLen >>> 0;
    view.setUint32(totalLen - 8, highBits, false);
    view.setUint32(totalLen - 4, lowBits, false);
    let h0 = 0x6a09e667;
    let h1 = 0xbb67ae85;
    let h2 = 0x3c6ef372;
    let h3 = 0xa54ff53a;
    let h4 = 0x510e527f;
    let h5 = 0x9b05688c;
    let h6 = 0x1f83d9ab;
    let h7 = 0x5be0cd19;
    const w = new Uint32Array(64);
    for (let offset = 0; offset < totalLen; offset += 64) {
        for (let i = 0; i < 16; i++) {
            w[i] = view.getUint32(offset + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const w15 = w[i - 15] ?? 0;
            const w2 = w[i - 2] ?? 0;
            const w16 = w[i - 16] ?? 0;
            const w7 = w[i - 7] ?? 0;
            const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
            const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
            w[i] = (w16 + s0 + w7 + s1) >>> 0;
        }
        let a = h0;
        let b = h1;
        let c = h2;
        let d = h3;
        let e = h4;
        let f = h5;
        let g = h6;
        let h = h7;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const ki = SHA256_K[i] ?? 0;
            const wi = w[i] ?? 0;
            const temp1 = (h + S1 + ch + ki + wi) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }
        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
        h5 = (h5 + f) >>> 0;
        h6 = (h6 + g) >>> 0;
        h7 = (h7 + h) >>> 0;
    }
    return [h0, h1, h2, h3, h4, h5, h6, h7]
        .map((word) => word.toString(16).padStart(8, "0"))
        .join("");
}
export function sha256Hex(text) {
    return sha256Bytes(utf8Bytes(text));
}
export class ToolScopeViolationError extends Error {
    activeIntent;
    toolName;
    allowedIntents;
    reason;
    constructor(params) {
        const reason = params.reason ?? "intent_not_allowed";
        const allowed = params.allowedIntents.length > 0
            ? [...params.allowedIntents].sort().join(", ")
            : "<none>";
        const message = reason === "read_only_required"
            ? `Tool '${params.toolName}' is mutating (readOnly=false) and cannot execute when read-only mode is required (active intent: '${params.activeIntent}').`
            : `Tool '${params.toolName}' is not permitted for intent '${params.activeIntent}' (allowed intents: ${allowed}).`;
        super(message);
        this.name = "ToolScopeViolationError";
        this.activeIntent = params.activeIntent;
        this.toolName = params.toolName;
        this.allowedIntents = Object.freeze([...params.allowedIntents]);
        this.reason = reason;
    }
}
function escapeRegExp(literal) {
    return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
export class IntentRouter {
    rules;
    classifier;
    minConfidence;
    fallbackIntent;
    knownIntents;
    constructor(options = {}) {
        const minConfidence = options.minConfidence ?? 0.75;
        if (!Number.isFinite(minConfidence) ||
            minConfidence < 0 ||
            minConfidence > 1) {
            throw new RangeError("minConfidence must be a finite number between 0.0 and 1.0");
        }
        this.rules = [...(options.rules ?? [])].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
        this.classifier = options.classifier;
        this.minConfidence = minConfidence;
        this.fallbackIntent = options.fallbackIntent ?? "triage";
        this.knownIntents = options.knownIntents
            ? new Set(options.knownIntents)
            : undefined;
    }
    route(utterance) {
        const normalized = utterance.trim();
        if (normalized.length === 0) {
            return {
                intent: this.fallbackIntent,
                confidence: 0,
                matchedBy: "fallback",
                reason: "empty_utterance",
            };
        }
        const lowered = normalized.toLowerCase();
        for (const rule of this.rules) {
            if (rule.predicate && rule.predicate(normalized)) {
                return {
                    intent: rule.intent,
                    confidence: 1.0,
                    matchedBy: "rule",
                    reason: `predicate:${rule.intent}`,
                };
            }
            for (const kw of rule.keywords ?? []) {
                const kwClean = kw.trim().toLowerCase();
                if (kwClean.length === 0) {
                    continue;
                }
                const pattern = new RegExp(`(?<!\\w)${escapeRegExp(kwClean)}(?!\\w)`);
                if (pattern.test(lowered)) {
                    return {
                        intent: rule.intent,
                        confidence: 1.0,
                        matchedBy: "rule",
                        reason: `keyword:${kwClean}`,
                    };
                }
            }
        }
        if (this.classifier) {
            const classified = this.classifier(normalized);
            const confidence = Number.isFinite(classified.confidence)
                ? Math.max(0, Math.min(1, classified.confidence))
                : 0;
            if (this.knownIntents && !this.knownIntents.has(classified.intent)) {
                return {
                    intent: this.fallbackIntent,
                    confidence,
                    matchedBy: "fallback",
                    reason: `unknown_intent:${classified.intent}`,
                };
            }
            if (confidence >= this.minConfidence) {
                return {
                    intent: classified.intent,
                    confidence,
                    matchedBy: "classifier",
                    reason: "confidence_threshold_met",
                };
            }
            return {
                intent: this.fallbackIntent,
                confidence,
                matchedBy: "fallback",
                reason: `below_confidence_threshold:${confidence.toFixed(2)}<${this.minConfidence.toFixed(2)}`,
            };
        }
        return {
            intent: this.fallbackIntent,
            confidence: 0,
            matchedBy: "fallback",
            reason: "no_rule_matched_and_no_classifier",
        };
    }
}
export class ScopedToolRegistry {
    tools = new Map();
    register(spec) {
        if (spec.name.trim().length === 0) {
            throw new Error("Tool name must be non-empty");
        }
        if (this.tools.has(spec.name)) {
            throw new Error(`Duplicate tool registration: '${spec.name}'`);
        }
        this.tools.set(spec.name, {
            name: spec.name,
            description: spec.description,
            allowedIntents: new Set(spec.allowedIntents),
            readOnly: spec.readOnly ?? true,
            handler: (payload) => spec.handler(payload),
        });
    }
    toolsForIntent(intent, options = {}) {
        const scoped = [];
        for (const spec of this.tools.values()) {
            if (!spec.allowedIntents.has(intent)) {
                continue;
            }
            if (options.readOnlyOnly && !spec.readOnly) {
                continue;
            }
            scoped.push(Object.freeze({
                name: spec.name,
                description: spec.description,
                allowedIntents: Object.freeze([...spec.allowedIntents]),
                readOnly: spec.readOnly,
                handler: spec.handler,
            }));
        }
        return scoped;
    }
    exportManifest(intent, options = {}) {
        return this.toolsForIntent(intent, options).map((spec) => ({
            name: spec.name,
            description: spec.description,
            readOnly: spec.readOnly ?? true,
        }));
    }
    invoke(params) {
        const spec = this.tools.get(params.toolName);
        if (!spec) {
            throw new Error(`Unknown tool: '${params.toolName}'`);
        }
        if (!spec.allowedIntents.has(params.activeIntent)) {
            throw new ToolScopeViolationError({
                activeIntent: params.activeIntent,
                toolName: params.toolName,
                allowedIntents: [...spec.allowedIntents],
                reason: "intent_not_allowed",
            });
        }
        if (params.requireReadOnly && !spec.readOnly) {
            throw new ToolScopeViolationError({
                activeIntent: params.activeIntent,
                toolName: params.toolName,
                allowedIntents: [...spec.allowedIntents],
                reason: "read_only_required",
            });
        }
        return spec.handler(params.payload);
    }
}
export class DelegationDeniedError extends Error {
    reason;
    caller;
    worker;
    lineage;
    constructor(params) {
        super(`[${params.reason}] ${params.caller} -> ${params.worker}: ${params.detail}`);
        this.name = "DelegationDeniedError";
        this.reason = params.reason;
        this.caller = params.caller;
        this.worker = params.worker;
        this.lineage = Object.freeze([...params.lineage]);
    }
}
export class SupervisorGate {
    allowedTransitions;
    maxDepth;
    maxTotalDelegations;
    maxCallsPerWorker;
    preventCycles;
    workers = new Map();
    totalDelegations = 0;
    workerCounts = new Map();
    recordedReceipts = [];
    constructor(policy) {
        const maxDepth = policy.maxDepth ?? 3;
        const maxTotalDelegations = policy.maxTotalDelegations ?? 10;
        const maxCallsPerWorker = policy.maxCallsPerWorker ?? 3;
        if (!Number.isInteger(maxDepth) || maxDepth < 1) {
            throw new RangeError("maxDepth must be an integer >= 1");
        }
        if (!Number.isInteger(maxTotalDelegations) || maxTotalDelegations < 1) {
            throw new RangeError("maxTotalDelegations must be an integer >= 1");
        }
        if (!Number.isInteger(maxCallsPerWorker) || maxCallsPerWorker < 1) {
            throw new RangeError("maxCallsPerWorker must be an integer >= 1");
        }
        const map = new Map();
        for (const [caller, targets] of Object.entries(policy.allowedTransitions)) {
            map.set(caller, new Set(targets));
        }
        this.allowedTransitions = map;
        this.maxDepth = maxDepth;
        this.maxTotalDelegations = maxTotalDelegations;
        this.maxCallsPerWorker = maxCallsPerWorker;
        this.preventCycles = policy.preventCycles ?? true;
    }
    registerWorker(name, handler) {
        if (name.trim().length === 0) {
            throw new Error("Worker name must be non-empty");
        }
        this.workers.set(name, (task) => handler(task));
    }
    get remainingBudget() {
        return Math.max(0, this.maxTotalDelegations - this.totalDelegations);
    }
    get receipts() {
        return [...this.recordedReceipts];
    }
    delegate(task) {
        const baseLineage = task.lineage && task.lineage.length > 0
            ? [...task.lineage]
            : [task.caller];
        if (baseLineage[baseLineage.length - 1] !== task.caller) {
            baseLineage.push(task.caller);
        }
        const allowedTargets = this.allowedTransitions.get(task.caller);
        if (!allowedTargets || !allowedTargets.has(task.worker)) {
            throw new DelegationDeniedError({
                reason: "TRANSITION_FORBIDDEN",
                caller: task.caller,
                worker: task.worker,
                lineage: baseLineage,
                detail: `Transition '${task.caller}' -> '${task.worker}' is not permitted`,
            });
        }
        if (this.preventCycles && baseLineage.includes(task.worker)) {
            throw new DelegationDeniedError({
                reason: "CYCLE_DETECTED",
                caller: task.caller,
                worker: task.worker,
                lineage: baseLineage,
                detail: `Cycle detected along lineage ${[...baseLineage, task.worker].join(" -> ")}`,
            });
        }
        const depth = baseLineage.length;
        if (depth > this.maxDepth) {
            throw new DelegationDeniedError({
                reason: "MAX_DEPTH_EXCEEDED",
                caller: task.caller,
                worker: task.worker,
                lineage: baseLineage,
                detail: `Delegation depth ${depth} exceeds maxDepth=${this.maxDepth}`,
            });
        }
        if (this.totalDelegations >= this.maxTotalDelegations) {
            throw new DelegationDeniedError({
                reason: "BUDGET_EXHAUSTED",
                caller: task.caller,
                worker: task.worker,
                lineage: baseLineage,
                detail: `Global limit of ${this.maxTotalDelegations} delegations reached`,
            });
        }
        const handler = this.workers.get(task.worker);
        if (!handler) {
            throw new DelegationDeniedError({
                reason: "UNKNOWN_WORKER",
                caller: task.caller,
                worker: task.worker,
                lineage: baseLineage,
                detail: `Worker '${task.worker}' is not registered`,
            });
        }
        const usedCalls = this.workerCounts.get(task.worker) ?? 0;
        if (usedCalls >= this.maxCallsPerWorker) {
            throw new DelegationDeniedError({
                reason: "WORKER_QUOTA_EXCEEDED",
                caller: task.caller,
                worker: task.worker,
                lineage: baseLineage,
                detail: `Worker '${task.worker}' reached quota (${this.maxCallsPerWorker})`,
            });
        }
        this.totalDelegations += 1;
        const seq = this.totalDelegations;
        this.workerCounts.set(task.worker, usedCalls + 1);
        const nextLineage = Object.freeze([...baseLineage, task.worker]);
        const forwardedTask = {
            taskId: task.taskId,
            caller: task.caller,
            worker: task.worker,
            objective: task.objective,
            payload: task.payload,
            lineage: nextLineage,
        };
        const output = handler(forwardedTask);
        const receipt = Object.freeze({
            taskId: task.taskId,
            caller: task.caller,
            worker: task.worker,
            depth,
            sequenceNum: seq,
            lineage: nextLineage,
            output,
        });
        this.recordedReceipts.push(receipt);
        return receipt;
    }
}
// ---------------------------------------------------------------------------
// Skill 3: Pass-by-Reference Blackboard
// ---------------------------------------------------------------------------
export class BlackboardError extends Error {
    constructor(message) {
        super(message);
        this.name = "BlackboardError";
    }
}
export class BlackboardAccessError extends BlackboardError {
    constructor(message) {
        super(message);
        this.name = "BlackboardAccessError";
    }
}
export class BlackboardIntegrityError extends BlackboardError {
    constructor(message) {
        super(message);
        this.name = "BlackboardIntegrityError";
    }
}
export class BlackboardExpiredError extends BlackboardError {
    constructor(message) {
        super(message);
        this.name = "BlackboardExpiredError";
    }
}
export class PassByRefBlackboard {
    maxSummaryChars;
    clock;
    records = new Map();
    versionsByKey = new Map();
    constructor(options = {}) {
        const maxSummaryChars = options.maxSummaryChars ?? 240;
        if (!Number.isInteger(maxSummaryChars) || maxSummaryChars < 16) {
            throw new RangeError("maxSummaryChars must be an integer >= 16");
        }
        this.maxSummaryChars = maxSummaryChars;
        this.clock = options.clock ?? (() => Date.now());
    }
    put(params) {
        if (params.key.trim().length === 0) {
            throw new Error("Artifact key must be non-empty");
        }
        if (params.ttlMs !== undefined &&
            (!Number.isFinite(params.ttlMs) || params.ttlMs <= 0)) {
            throw new RangeError("ttlMs must be a finite positive number when provided");
        }
        const serialized = canonicalJson(params.value);
        const bytes = utf8Bytes(serialized);
        const digest = sha256Bytes(bytes);
        const version = (this.versionsByKey.get(params.key) ?? 0) + 1;
        this.versionsByKey.set(params.key, version);
        let cleanSummary = params.summary.trim().replace(/\s+/g, " ");
        if (cleanSummary.length > this.maxSummaryChars) {
            cleanSummary = cleanSummary.slice(0, this.maxSummaryChars - 3) + "...";
        }
        const nowMs = this.clock();
        const expiresAtMs = params.ttlMs !== undefined ? nowMs + params.ttlMs : null;
        const refId = `ref:${params.key}:v${version}:${digest.slice(0, 12)}`;
        const pointer = Object.freeze({
            refId,
            key: params.key,
            kind: params.kind,
            sha256: digest,
            byteSize: bytes.length,
            summary: cleanSummary,
            producer: params.producer,
            version,
            createdAtMs: nowMs,
            expiresAtMs,
            toContextToken() {
                return {
                    refId,
                    kind: params.kind,
                    byteSize: bytes.length,
                    sha256Prefix: digest.slice(0, 16),
                    version,
                    summary: cleanSummary,
                };
            },
        });
        this.records.set(refId, {
            pointer,
            serializedJson: serialized,
            allowedReaders: params.allowedReaders
                ? new Set(params.allowedReaders)
                : null,
        });
        return pointer;
    }
    resolve(refId, reader) {
        const record = this.records.get(refId);
        if (!record) {
            throw new Error(`Unknown artifact reference: '${refId}'`);
        }
        const ptr = record.pointer;
        const nowMs = this.clock();
        if (ptr.expiresAtMs !== null && nowMs >= ptr.expiresAtMs) {
            throw new BlackboardExpiredError(`Artifact '${refId}' expired at ${ptr.expiresAtMs} (now=${nowMs})`);
        }
        if (record.allowedReaders !== null &&
            reader !== ptr.producer &&
            !record.allowedReaders.has(reader)) {
            throw new BlackboardAccessError(`Reader '${reader}' is not permitted to dereference '${refId}'`);
        }
        const actualDigest = sha256Hex(record.serializedJson);
        if (actualDigest !== ptr.sha256) {
            throw new BlackboardIntegrityError(`SHA-256 mismatch for '${refId}': expected ${ptr.sha256}, got ${actualDigest}`);
        }
        return JSON.parse(record.serializedJson);
    }
    pruneExpired() {
        const nowMs = this.clock();
        let removed = 0;
        for (const [refId, rec] of this.records.entries()) {
            if (rec.pointer.expiresAtMs !== null && nowMs >= rec.pointer.expiresAtMs) {
                this.records.delete(refId);
                removed += 1;
            }
        }
        return removed;
    }
}
