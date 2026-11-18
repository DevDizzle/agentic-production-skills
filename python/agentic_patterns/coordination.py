"""Coordination and context-hygiene patterns for multi-step AI agents.

Implements Skills 1-3:
1. IntentRouter and ScopedToolRegistry (intent-and-tool-routing)
2. SupervisorGate (supervisor-delegation-gate)
3. PassByRefBlackboard (pass-by-reference-blackboard)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
import re
import time
from typing import Callable, Generic, Mapping, Sequence, TypeVar

TIn = TypeVar("TIn")
TOut = TypeVar("TOut")
TPayload = TypeVar("TPayload")
TResult = TypeVar("TResult")


def canonical_json(value: object) -> str:
    """Serializes JSON-compatible data deterministically across Python and TypeScript."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(text: str) -> str:
    """Computes lowercase SHA-256 hex digest over UTF-8 bytes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Skill 1: Intent and Tool Routing
# ---------------------------------------------------------------------------


class ToolScopeViolationError(PermissionError):
    """Raised when an agent attempts to invoke a tool outside intent or read-only scope."""

    def __init__(
        self,
        *,
        active_intent: str,
        tool_name: str,
        allowed_intents: frozenset[str],
        reason: str = "intent_not_allowed",
    ) -> None:
        self.active_intent = active_intent
        self.tool_name = tool_name
        self.allowed_intents = allowed_intents
        self.reason = reason
        allowed = ", ".join(sorted(allowed_intents)) or "<none>"
        if reason == "read_only_required":
            msg = (
                f"Tool '{tool_name}' is mutating (read_only=False) and cannot execute "
                f"when read-only mode is required (active intent: '{active_intent}')."
            )
        else:
            msg = (
                f"Tool '{tool_name}' is not permitted for intent '{active_intent}' "
                f"(allowed intents: {allowed})."
            )
        super().__init__(msg)


@dataclass(frozen=True, slots=True)
class RouteRule:
    """Deterministic fast-path routing rule evaluated before model classification."""

    intent: str
    keywords: tuple[str, ...] = ()
    predicate: Callable[[str], bool] | None = None
    priority: int = 0


@dataclass(frozen=True, slots=True)
class IntentDecision:
    """Resolved routing outcome including confidence and provenance."""

    intent: str
    confidence: float
    matched_by: str
    reason: str


ClassifierFn = Callable[[str], tuple[str, float]]


class IntentRouter:
    """Two-stage intent router combining deterministic fast-path rules and confidence gating."""

    def __init__(
        self,
        *,
        rules: Sequence[RouteRule] = (),
        classifier: ClassifierFn | None = None,
        min_confidence: float = 0.75,
        fallback_intent: str = "triage",
        known_intents: set[str] | frozenset[str] | None = None,
    ) -> None:
        if (
            isinstance(min_confidence, bool)
            or not math.isfinite(min_confidence)
            or not 0.0 <= min_confidence <= 1.0
        ):
            raise ValueError("min_confidence must be a finite float between 0.0 and 1.0")
        self._rules = tuple(sorted(rules, key=lambda r: r.priority, reverse=True))
        self._classifier = classifier
        self._min_confidence = float(min_confidence)
        self._fallback_intent = fallback_intent
        self._known_intents = frozenset(known_intents) if known_intents is not None else None

    def route(self, utterance: str) -> IntentDecision:
        normalized = utterance.strip()
        if not normalized:
            return IntentDecision(
                intent=self._fallback_intent,
                confidence=0.0,
                matched_by="fallback",
                reason="empty_utterance",
            )

        lowered = normalized.lower()
        for rule in self._rules:
            if rule.predicate is not None and rule.predicate(normalized):
                return IntentDecision(
                    intent=rule.intent,
                    confidence=1.0,
                    matched_by="rule",
                    reason=f"predicate:{rule.intent}",
                )
            for kw in rule.keywords:
                kw_clean = kw.strip().lower()
                if not kw_clean:
                    continue
                pattern = r"(?<!\w)" + re.escape(kw_clean) + r"(?!\w)"
                if re.search(pattern, lowered):
                    return IntentDecision(
                        intent=rule.intent,
                        confidence=1.0,
                        matched_by="rule",
                        reason=f"keyword:{kw_clean}",
                    )

        if self._classifier is not None:
            candidate_intent, raw_confidence = self._classifier(normalized)
            raw_float = float(raw_confidence)
            confidence = (
                max(0.0, min(1.0, raw_float))
                if math.isfinite(raw_float)
                else 0.0
            )
            if (
                self._known_intents is not None
                and candidate_intent not in self._known_intents
            ):
                return IntentDecision(
                    intent=self._fallback_intent,
                    confidence=confidence,
                    matched_by="fallback",
                    reason=f"unknown_intent:{candidate_intent}",
                )
            if confidence >= self._min_confidence:
                return IntentDecision(
                    intent=candidate_intent,
                    confidence=confidence,
                    matched_by="classifier",
                    reason="confidence_threshold_met",
                )
            return IntentDecision(
                intent=self._fallback_intent,
                confidence=confidence,
                matched_by="fallback",
                reason=f"below_confidence_threshold:{confidence:.2f}<{self._min_confidence:.2f}",
            )

        return IntentDecision(
            intent=self._fallback_intent,
            confidence=0.0,
            matched_by="fallback",
            reason="no_rule_matched_and_no_classifier",
        )


@dataclass(frozen=True, slots=True)
class ToolSpec(Generic[TIn, TOut]):
    """Typed tool registration binding a handler to explicit intent scopes."""

    name: str
    description: str
    allowed_intents: frozenset[str]
    handler: Callable[[TIn], TOut]
    read_only: bool = True


class ScopedToolRegistry:
    """Least-privilege tool registry enforcing both prompt-time filtering and runtime checks."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec[object, object]] = {}

    def register(self, spec: ToolSpec[TIn, TOut]) -> None:
        if not spec.name.strip():
            raise ValueError("Tool name must be non-empty")
        if spec.name in self._tools:
            raise ValueError(f"Duplicate tool registration: '{spec.name}'")
        self._tools[spec.name] = spec  # type: ignore[assignment]

    def tools_for_intent(
        self,
        intent: str,
        *,
        read_only_only: bool = False,
    ) -> list[ToolSpec[object, object]]:
        scoped: list[ToolSpec[object, object]] = []
        for spec in self._tools.values():
            if intent not in spec.allowed_intents:
                continue
            if read_only_only and not spec.read_only:
                continue
            scoped.append(spec)
        return scoped

    def export_manifest(
        self,
        intent: str,
        *,
        read_only_only: bool = False,
    ) -> list[dict[str, object]]:
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "read_only": spec.read_only,
            }
            for spec in self.tools_for_intent(intent, read_only_only=read_only_only)
        ]

    def invoke(
        self,
        *,
        active_intent: str,
        tool_name: str,
        payload: object,
        require_read_only: bool = False,
    ) -> object:
        if tool_name not in self._tools:
            raise KeyError(f"Unknown tool: '{tool_name}'")
        spec = self._tools[tool_name]
        if active_intent not in spec.allowed_intents:
            raise ToolScopeViolationError(
                active_intent=active_intent,
                tool_name=tool_name,
                allowed_intents=spec.allowed_intents,
                reason="intent_not_allowed",
            )
        if require_read_only and not spec.read_only:
            raise ToolScopeViolationError(
                active_intent=active_intent,
                tool_name=tool_name,
                allowed_intents=spec.allowed_intents,
                reason="read_only_required",
            )
        return spec.handler(payload)


# ---------------------------------------------------------------------------
# Skill 2: Supervisor Delegation Gate
# ---------------------------------------------------------------------------


class DenialReason(str, Enum):
    """Deterministic denial codes when a delegation request is blocked."""

    UNKNOWN_WORKER = "UNKNOWN_WORKER"
    TRANSITION_FORBIDDEN = "TRANSITION_FORBIDDEN"
    CYCLE_DETECTED = "CYCLE_DETECTED"
    MAX_DEPTH_EXCEEDED = "MAX_DEPTH_EXCEEDED"
    WORKER_QUOTA_EXCEEDED = "WORKER_QUOTA_EXCEEDED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class DelegationDeniedError(RuntimeError):
    """Raised when a supervisor or subagent violates delegation topology or budget limits."""

    def __init__(
        self,
        *,
        reason: DenialReason,
        caller: str,
        worker: str,
        lineage: tuple[str, ...],
        detail: str,
    ) -> None:
        self.reason = reason
        self.caller = caller
        self.worker = worker
        self.lineage = lineage
        super().__init__(f"[{reason.value}] {caller} -> {worker}: {detail}")


@dataclass(frozen=True, slots=True)
class DelegationPolicy:
    """Topology, depth, and call-budget policy enforced across a workflow run."""

    allowed_transitions: Mapping[str, frozenset[str]]
    max_depth: int = 3
    max_total_delegations: int = 10
    max_calls_per_worker: int = 3
    prevent_cycles: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.max_depth, bool) or self.max_depth < 1:
            raise ValueError("max_depth must be an integer >= 1")
        if (
            isinstance(self.max_total_delegations, bool)
            or self.max_total_delegations < 1
        ):
            raise ValueError("max_total_delegations must be an integer >= 1")
        if (
            isinstance(self.max_calls_per_worker, bool)
            or self.max_calls_per_worker < 1
        ):
            raise ValueError("max_calls_per_worker must be an integer >= 1")


@dataclass(frozen=True, slots=True)
class DelegationTask(Generic[TPayload]):
    """Structured task contract passed across an agent handoff boundary."""

    task_id: str
    caller: str
    worker: str
    objective: str
    payload: TPayload
    lineage: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DelegationReceipt(Generic[TResult]):
    """Execution telemetry emitted for each approved delegation hop."""

    task_id: str
    caller: str
    worker: str
    depth: int
    sequence_num: int
    lineage: tuple[str, ...]
    output: TResult


class SupervisorGate:
    """Enforces cycle prevention, transition allowlists, depth caps, and budgets."""

    def __init__(self, policy: DelegationPolicy) -> None:
        self._policy = policy
        self._workers: dict[str, Callable[[DelegationTask[object]], object]] = {}
        self._total_delegations = 0
        self._worker_counts: dict[str, int] = {}
        self._receipts: list[DelegationReceipt[object]] = []

    def register_worker(
        self,
        name: str,
        handler: Callable[[DelegationTask[TPayload]], TResult],
    ) -> None:
        if not name.strip():
            raise ValueError("Worker name must be non-empty")
        self._workers[name] = handler  # type: ignore[assignment]

    @property
    def remaining_budget(self) -> int:
        return max(0, self._policy.max_total_delegations - self._total_delegations)

    @property
    def receipts(self) -> tuple[DelegationReceipt[object], ...]:
        return tuple(self._receipts)

    def delegate(self, task: DelegationTask[TPayload]) -> DelegationReceipt[object]:
        effective_lineage = task.lineage if task.lineage else (task.caller,)
        if effective_lineage[-1] != task.caller:
            effective_lineage = (*effective_lineage, task.caller)

        allowed_targets = self._policy.allowed_transitions.get(
            task.caller, frozenset()
        )
        if task.worker not in allowed_targets:
            raise DelegationDeniedError(
                reason=DenialReason.TRANSITION_FORBIDDEN,
                caller=task.caller,
                worker=task.worker,
                lineage=effective_lineage,
                detail=f"Transition '{task.caller}' -> '{task.worker}' is not in allowed_transitions",
            )

        if self._policy.prevent_cycles and task.worker in effective_lineage:
            raise DelegationDeniedError(
                reason=DenialReason.CYCLE_DETECTED,
                caller=task.caller,
                worker=task.worker,
                lineage=effective_lineage,
                detail=f"Cycle detected along lineage {' -> '.join((*effective_lineage, task.worker))}",
            )

        depth = len(effective_lineage)
        if depth > self._policy.max_depth:
            raise DelegationDeniedError(
                reason=DenialReason.MAX_DEPTH_EXCEEDED,
                caller=task.caller,
                worker=task.worker,
                lineage=effective_lineage,
                detail=f"Delegation depth {depth} exceeds max_depth={self._policy.max_depth}",
            )

        if self._total_delegations >= self._policy.max_total_delegations:
            raise DelegationDeniedError(
                reason=DenialReason.BUDGET_EXHAUSTED,
                caller=task.caller,
                worker=task.worker,
                lineage=effective_lineage,
                detail=f"Global limit of {self._policy.max_total_delegations} delegations reached",
            )

        if task.worker not in self._workers:
            raise DelegationDeniedError(
                reason=DenialReason.UNKNOWN_WORKER,
                caller=task.caller,
                worker=task.worker,
                lineage=effective_lineage,
                detail=f"Worker '{task.worker}' is not registered",
            )

        worker_calls = self._worker_counts.get(task.worker, 0)
        if worker_calls >= self._policy.max_calls_per_worker:
            raise DelegationDeniedError(
                reason=DenialReason.WORKER_QUOTA_EXCEEDED,
                caller=task.caller,
                worker=task.worker,
                lineage=effective_lineage,
                detail=f"Worker '{task.worker}' reached quota ({self._policy.max_calls_per_worker})",
            )

        self._total_delegations += 1
        seq = self._total_delegations
        self._worker_counts[task.worker] = worker_calls + 1

        next_lineage = (*effective_lineage, task.worker)
        forwarded_task: DelegationTask[object] = DelegationTask(
            task_id=task.task_id,
            caller=task.caller,
            worker=task.worker,
            objective=task.objective,
            payload=task.payload,
            lineage=next_lineage,
        )
        output = self._workers[task.worker](forwarded_task)
        receipt: DelegationReceipt[object] = DelegationReceipt(
            task_id=task.task_id,
            caller=task.caller,
            worker=task.worker,
            depth=depth,
            sequence_num=seq,
            lineage=next_lineage,
            output=output,
        )
        self._receipts.append(receipt)
        return receipt


# ---------------------------------------------------------------------------
# Skill 3: Pass-by-Reference Blackboard
# ---------------------------------------------------------------------------


class BlackboardError(RuntimeError):
    """Base error for pass-by-reference blackboard operations."""


class BlackboardAccessError(BlackboardError):
    """Raised when an unauthorized reader attempts to dereference an artifact."""


class BlackboardIntegrityError(BlackboardError):
    """Raised when a stored artifact fails SHA-256 digest verification."""


class BlackboardExpiredError(BlackboardError):
    """Raised when dereferencing an artifact past its configured TTL."""


@dataclass(frozen=True, slots=True)
class ArtifactPointer:
    """Compact immutable pointer safe to pass inside LLM conversation context."""

    ref_id: str
    key: str
    kind: str
    sha256: str
    byte_size: int
    summary: str
    producer: str
    version: int
    created_at_ms: int
    expires_at_ms: int | None = None

    def to_context_token(self) -> dict[str, object]:
        return {
            "ref_id": self.ref_id,
            "kind": self.kind,
            "byte_size": self.byte_size,
            "sha256_prefix": self.sha256[:16],
            "version": self.version,
            "summary": self.summary,
        }


@dataclass(slots=True)
class _StoredArtifact:
    pointer: ArtifactPointer
    raw_bytes: bytes
    allowed_readers: frozenset[str] | None


class PassByRefBlackboard:
    """Out-of-band artifact store preventing large payloads from bloating prompt history."""

    def __init__(
        self,
        *,
        max_summary_chars: int = 240,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if isinstance(max_summary_chars, bool) or max_summary_chars < 16:
            raise ValueError("max_summary_chars must be an integer >= 16")
        self._max_summary_chars = max_summary_chars
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._records: dict[str, _StoredArtifact] = {}
        self._versions_by_key: dict[str, int] = {}

    def put(
        self,
        *,
        key: str,
        value: object,
        kind: str,
        summary: str,
        producer: str,
        allowed_readers: set[str] | frozenset[str] | None = None,
        ttl_ms: int | None = None,
    ) -> ArtifactPointer:
        if not key.strip():
            raise ValueError("Artifact key must be non-empty")
        if ttl_ms is not None and (isinstance(ttl_ms, bool) or ttl_ms <= 0):
            raise ValueError("ttl_ms must be a positive integer when provided")

        serialized = canonical_json(value).encode("utf-8")
        digest = hashlib.sha256(serialized).hexdigest()
        version = self._versions_by_key.get(key, 0) + 1
        self._versions_by_key[key] = version

        clean_summary = " ".join(summary.split())
        if len(clean_summary) > self._max_summary_chars:
            clean_summary = clean_summary[: self._max_summary_chars - 3] + "..."

        now_ms = self._clock()
        expires_at_ms = (now_ms + ttl_ms) if ttl_ms is not None else None
        ref_id = f"ref:{key}:v{version}:{digest[:12]}"
        pointer = ArtifactPointer(
            ref_id=ref_id,
            key=key,
            kind=kind,
            sha256=digest,
            byte_size=len(serialized),
            summary=clean_summary,
            producer=producer,
            version=version,
            created_at_ms=now_ms,
            expires_at_ms=expires_at_ms,
        )
        readers = (
            frozenset(allowed_readers)
            if allowed_readers is not None
            else None
        )
        self._records[ref_id] = _StoredArtifact(
            pointer=pointer,
            raw_bytes=serialized,
            allowed_readers=readers,
        )
        return pointer

    def resolve(self, ref_id: str, *, reader: str) -> object:
        if ref_id not in self._records:
            raise KeyError(f"Unknown artifact reference: '{ref_id}'")
        record = self._records[ref_id]
        ptr = record.pointer
        now_ms = self._clock()

        if ptr.expires_at_ms is not None and now_ms >= ptr.expires_at_ms:
            raise BlackboardExpiredError(
                f"Artifact '{ref_id}' expired at {ptr.expires_at_ms} (now={now_ms})"
            )

        if (
            record.allowed_readers is not None
            and reader != ptr.producer
            and reader not in record.allowed_readers
        ):
            raise BlackboardAccessError(
                f"Reader '{reader}' is not permitted to dereference '{ref_id}'"
            )

        actual_digest = hashlib.sha256(record.raw_bytes).hexdigest()
        if actual_digest != ptr.sha256:
            raise BlackboardIntegrityError(
                f"SHA-256 mismatch for '{ref_id}': expected {ptr.sha256}, got {actual_digest}"
            )

        return json.loads(record.raw_bytes.decode("utf-8"))

    def prune_expired(self) -> int:
        now_ms = self._clock()
        expired_ids = [
            ref_id
            for ref_id, rec in self._records.items()
            if rec.pointer.expires_at_ms is not None
            and now_ms >= rec.pointer.expires_at_ms
        ]
        for ref_id in expired_ids:
            del self._records[ref_id]
        return len(expired_ids)
