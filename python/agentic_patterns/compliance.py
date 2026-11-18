"""Governance, policy anchoring, independent verification, and causal auditability.

Implements Skills 4-6:
4. ConstraintEnvelope (constraint-anchoring)
5. IndependentAuditorGate (independent-auditor-gate)
6. CausalAuditLedger (causal-audit-ledger)
"""

from __future__ import annotations

from collections import deque
import copy
from dataclasses import dataclass
import re
import time
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

from .coordination import canonical_json, sha256_hex


# ---------------------------------------------------------------------------
# Skill 4: Constraint Anchoring
# ---------------------------------------------------------------------------


class ConstraintTamperError(RuntimeError):
    """Raised when an anchored constraint envelope fails cryptographic fingerprint check."""


@dataclass(frozen=True, slots=True)
class Invariant:
    """Single immutable policy invariant evaluated before action execution."""

    rule_id: str
    statement: str
    severity: str
    validator: Callable[[Mapping[str, object]], tuple[bool, str]]


@dataclass(frozen=True, slots=True)
class ConstraintViolation:
    """Structured violation emitted when a proposed action breaks an invariant."""

    rule_id: str
    severity: str
    statement: str
    detail: str


@dataclass(frozen=True, slots=True)
class ConstraintCheckResult:
    """Aggregate result of checking an action against all anchored invariants."""

    allowed: bool
    envelope_id: str
    fingerprint: str
    violations: tuple[ConstraintViolation, ...]


class ConstraintEnvelope:
    """Cryptographically fingerprinted policy envelope resisting multi-turn drift."""

    def __init__(
        self,
        *,
        envelope_id: str,
        invariants: Sequence[Invariant],
    ) -> None:
        if not envelope_id.strip():
            raise ValueError("envelope_id must be non-empty")
        if not invariants:
            raise ValueError("ConstraintEnvelope requires at least one Invariant")
        seen_ids: set[str] = set()
        ordered = sorted(invariants, key=lambda inv: inv.rule_id)
        for inv in ordered:
            if inv.rule_id in seen_ids:
                raise ValueError(f"Duplicate invariant rule_id: '{inv.rule_id}'")
            seen_ids.add(inv.rule_id)
        self._envelope_id = envelope_id
        self._invariants = tuple(ordered)
        self._fingerprint = self._compute_fingerprint()

    @property
    def envelope_id(self) -> str:
        return self._envelope_id

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def invariants(self) -> tuple[Invariant, ...]:
        return self._invariants

    def _compute_fingerprint(self) -> str:
        canonical_spec = [
            {
                "rule_id": inv.rule_id,
                "severity": inv.severity,
                "statement": inv.statement,
            }
            for inv in self._invariants
        ]
        return sha256_hex(
            canonical_json(
                {
                    "envelope_id": self._envelope_id,
                    "rules": canonical_spec,
                }
            )
        )

    def verify_fingerprint(self, expected_fingerprint: str) -> None:
        live = self._compute_fingerprint()
        if live != expected_fingerprint or self._fingerprint != expected_fingerprint:
            raise ConstraintTamperError(
                f"Constraint envelope '{self._envelope_id}' fingerprint mismatch: "
                f"expected {expected_fingerprint}, computed {live}"
            )

    @staticmethod
    def should_reanchor(
        *,
        turn_index: int,
        every_n_turns: int = 4,
        compacted: bool = False,
    ) -> bool:
        if isinstance(every_n_turns, bool) or every_n_turns < 1:
            raise ValueError("every_n_turns must be >= 1")
        if compacted:
            return True
        return turn_index > 0 and (turn_index % every_n_turns == 0)

    def render_anchor_block(self, *, turn_index: int) -> str:
        lines = [
            f"[ANCHORED_CONSTRAINTS id={self._envelope_id} sha256={self._fingerprint[:16]} turn={turn_index}]"
        ]
        for inv in self._invariants:
            lines.append(f"- [{inv.severity}] ({inv.rule_id}) {inv.statement}")
        lines.append("[/ANCHORED_CONSTRAINTS]")
        return "\n".join(lines)

    def evaluate_action(
        self,
        action_context: Mapping[str, object],
        *,
        expected_fingerprint: str | None = None,
    ) -> ConstraintCheckResult:
        if expected_fingerprint is not None:
            self.verify_fingerprint(expected_fingerprint)
        violations: list[ConstraintViolation] = []
        for inv in self._invariants:
            passed, detail = inv.validator(action_context)
            if not passed:
                violations.append(
                    ConstraintViolation(
                        rule_id=inv.rule_id,
                        severity=inv.severity,
                        statement=inv.statement,
                        detail=detail,
                    )
                )
        return ConstraintCheckResult(
            allowed=len(violations) == 0,
            envelope_id=self._envelope_id,
            fingerprint=self._fingerprint,
            violations=tuple(violations),
        )


# ---------------------------------------------------------------------------
# Skill 5: Independent Auditor Gate
# ---------------------------------------------------------------------------

_REASONING_CLOSED_RE = re.compile(
    r"<(think|thought|scratchpad|reasoning|internal_monologue)(?:\s[^>]*)?>.*?</\1\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)

_REASONING_UNCLOSED_RE = re.compile(
    r"<(think|thought|scratchpad|reasoning|internal_monologue)(?:\s[^>]*)?>.*$",
    flags=re.IGNORECASE | re.DOTALL,
)


def strip_reasoning_trace(raw_output: str) -> str:
    """Strips generator chain-of-thought tags (including attributes and truncated blocks)."""
    cleaned = raw_output
    while True:
        next_cleaned = _REASONING_CLOSED_RE.sub("", cleaned)
        if next_cleaned == cleaned:
            break
        cleaned = next_cleaned
    cleaned = _REASONING_UNCLOSED_RE.sub("", cleaned)
    return cleaned.strip()


@dataclass(frozen=True, slots=True)
class AuditCriterion:
    """Rubric item with optional fast deterministic pre-check."""

    criterion_id: str
    description: str
    deterministic_check: (
        Callable[[str, Mapping[str, object]], tuple[bool, str]] | None
    ) = None


@dataclass(frozen=True, slots=True)
class AuditPacket:
    """Context-isolated verification input containing zero generator rationalizations."""

    specification: str
    candidate_output: str
    criteria: tuple[tuple[str, str], ...]
    evidence: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class AuditVerdict:
    """Outcome of deterministic checks and independent auditor evaluation."""

    approved: bool
    auditor_id: str
    failed_criteria: tuple[str, ...]
    findings: tuple[str, ...]
    remediation: str


@dataclass(frozen=True, slots=True)
class GuardedGenerationResult:
    """Bounded generator-auditor loop result."""

    approved: bool
    final_output: str
    revisions_used: int
    verdicts: tuple[AuditVerdict, ...]


AuditorFn = Callable[[AuditPacket], AuditVerdict]


class IndependentAuditorGate:
    """Evaluates artifacts in isolated context after stripping generator rationalizations."""

    def __init__(
        self,
        *,
        criteria: Sequence[AuditCriterion],
        auditors: Sequence[tuple[str, AuditorFn]] = (),
    ) -> None:
        if not criteria:
            raise ValueError("At least one AuditCriterion is required")
        self._criteria = tuple(criteria)
        self._auditors = tuple(auditors)

    def evaluate(
        self,
        *,
        specification: str,
        raw_candidate_output: str,
        evidence: Mapping[str, object] | None = None,
    ) -> AuditVerdict:
        ev: Mapping[str, object] = (
            MappingProxyType(copy.deepcopy(dict(evidence)))
            if evidence is not None
            else MappingProxyType({})
        )
        isolated_output = strip_reasoning_trace(raw_candidate_output)

        det_failed_ids: list[str] = []
        det_findings: list[str] = []
        for crit in self._criteria:
            if crit.deterministic_check is not None:
                passed, detail = crit.deterministic_check(isolated_output, ev)
                if not passed:
                    det_failed_ids.append(crit.criterion_id)
                    det_findings.append(f"[{crit.criterion_id}] {detail}")

        if det_failed_ids:
            return AuditVerdict(
                approved=False,
                auditor_id="deterministic_precheck",
                failed_criteria=tuple(det_failed_ids),
                findings=tuple(det_findings),
                remediation="Resolve deterministic rubric failures: "
                + "; ".join(det_findings),
            )

        packet = AuditPacket(
            specification=specification,
            candidate_output=isolated_output,
            criteria=tuple((c.criterion_id, c.description) for c in self._criteria),
            evidence=ev,
        )

        failed_ids: list[str] = []
        findings: list[str] = []
        remediations: list[str] = []
        auditor_labels: list[str] = []
        any_rejected = False

        for auditor_id, auditor_fn in self._auditors:
            auditor_labels.append(auditor_id)
            verdict = auditor_fn(packet)
            if not verdict.approved:
                any_rejected = True
            if not verdict.approved or verdict.failed_criteria or verdict.findings:
                for cid in verdict.failed_criteria:
                    if cid not in failed_ids:
                        failed_ids.append(cid)
                findings.extend(f"[{auditor_id}] {f}" for f in verdict.findings)
                if verdict.remediation:
                    remediations.append(verdict.remediation)

        approved = (not any_rejected) and len(failed_ids) == 0 and len(findings) == 0
        return AuditVerdict(
            approved=approved,
            auditor_id="+".join(auditor_labels) if auditor_labels else "deterministic_only",
            failed_criteria=tuple(failed_ids),
            findings=tuple(findings),
            remediation=" | ".join(remediations),
        )

    def run_guarded_loop(
        self,
        *,
        specification: str,
        generator: Callable[[str, tuple[AuditVerdict, ...]], str],
        evidence: Mapping[str, object] | None = None,
        max_revisions: int = 2,
    ) -> GuardedGenerationResult:
        if isinstance(max_revisions, bool) or max_revisions < 0:
            raise ValueError("max_revisions must be >= 0")
        verdicts: list[AuditVerdict] = []
        latest_clean = ""

        for attempt in range(max_revisions + 1):
            raw_candidate = generator(specification, tuple(verdicts))
            latest_clean = strip_reasoning_trace(raw_candidate)
            verdict = self.evaluate(
                specification=specification,
                raw_candidate_output=raw_candidate,
                evidence=evidence,
            )
            verdicts.append(verdict)
            if verdict.approved:
                return GuardedGenerationResult(
                    approved=True,
                    final_output=latest_clean,
                    revisions_used=attempt,
                    verdicts=tuple(verdicts),
                )

        return GuardedGenerationResult(
            approved=False,
            final_output=latest_clean,
            revisions_used=max_revisions,
            verdicts=tuple(verdicts),
        )


# ---------------------------------------------------------------------------
# Skill 6: Causal Audit Ledger
# ---------------------------------------------------------------------------


class LedgerIntegrityError(RuntimeError):
    """Raised when causal parent validation or hash-chain verification fails."""


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """Immutable hash-chained and causally linked audit record."""

    seq: int
    entry_id: str
    timestamp_ms: int
    actor: str
    event_type: str
    parent_ids: tuple[str, ...]
    payload_digest: str
    metadata: Mapping[str, object]
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    """Verification summary across the sequential hash chain and causal DAG."""

    valid: bool
    checked_entries: int
    error: str | None = None
    broken_at_seq: int | None = None


class CausalAuditLedger:
    """Append-only causal DAG and SHA-256 hash chain for side-effecting agent actions."""

    GENESIS_HASH = "0" * 64

    def __init__(self, *, clock: Callable[[], int] | None = None) -> None:
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._entries: list[LedgerEntry] = []
        self._index_by_id: dict[str, int] = {}

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    @staticmethod
    def _compute_entry_hash(
        *,
        seq: int,
        entry_id: str,
        timestamp_ms: int,
        actor: str,
        event_type: str,
        parent_ids: tuple[str, ...],
        payload_digest: str,
        metadata: Mapping[str, object],
        prev_hash: str,
    ) -> str:
        body = {
            "actor": actor,
            "entry_id": entry_id,
            "event_type": event_type,
            "metadata": dict(metadata),
            "parent_ids": list(parent_ids),
            "payload_digest": payload_digest,
            "prev_hash": prev_hash,
            "seq": seq,
            "timestamp_ms": timestamp_ms,
        }
        return sha256_hex(canonical_json(body))

    def append(
        self,
        *,
        actor: str,
        event_type: str,
        payload: object,
        parent_ids: Sequence[str] = (),
        metadata: Mapping[str, object] | None = None,
        entry_id: str | None = None,
    ) -> LedgerEntry:
        seq = len(self._entries)
        resolved_id = entry_id or f"evt-{seq:06d}"
        if resolved_id in self._index_by_id:
            raise LedgerIntegrityError(f"Duplicate entry_id: '{resolved_id}'")

        dedup_parents = tuple(dict.fromkeys(parent_ids))
        for pid in dedup_parents:
            if pid not in self._index_by_id:
                raise LedgerIntegrityError(
                    f"Unknown causal parent_id '{pid}' referenced by '{resolved_id}'"
                )

        prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
        payload_digest = sha256_hex(canonical_json(payload))
        meta_copy: dict[str, object] = (
            copy.deepcopy(dict(metadata)) if metadata is not None else {}
        )
        ts = self._clock()

        entry_hash = self._compute_entry_hash(
            seq=seq,
            entry_id=resolved_id,
            timestamp_ms=ts,
            actor=actor,
            event_type=event_type,
            parent_ids=dedup_parents,
            payload_digest=payload_digest,
            metadata=meta_copy,
            prev_hash=prev_hash,
        )
        entry = LedgerEntry(
            seq=seq,
            entry_id=resolved_id,
            timestamp_ms=ts,
            actor=actor,
            event_type=event_type,
            parent_ids=dedup_parents,
            payload_digest=payload_digest,
            metadata=MappingProxyType(meta_copy),
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        self._index_by_id[resolved_id] = seq
        return entry

    def verify_payload(self, entry_id: str, candidate_payload: object) -> bool:
        if entry_id not in self._index_by_id:
            raise KeyError(f"Unknown entry_id: '{entry_id}'")
        entry = self._entries[self._index_by_id[entry_id]]
        return entry.payload_digest == sha256_hex(canonical_json(candidate_payload))

    def verify_chain(self) -> ChainVerificationResult:
        expected_prev = self.GENESIS_HASH
        seen_ids: dict[str, int] = {}

        for idx, entry in enumerate(self._entries):
            if entry.seq != idx:
                return ChainVerificationResult(
                    valid=False,
                    checked_entries=idx,
                    error=f"Sequence gap at index {idx}: found seq={entry.seq}",
                    broken_at_seq=idx,
                )
            if entry.prev_hash != expected_prev:
                return ChainVerificationResult(
                    valid=False,
                    checked_entries=idx,
                    error=f"prev_hash mismatch at seq={idx}",
                    broken_at_seq=idx,
                )
            for pid in entry.parent_ids:
                if pid not in seen_ids or seen_ids[pid] >= idx:
                    return ChainVerificationResult(
                        valid=False,
                        checked_entries=idx,
                        error=f"Invalid causal parent '{pid}' at seq={idx}",
                        broken_at_seq=idx,
                    )
            recomputed = self._compute_entry_hash(
                seq=entry.seq,
                entry_id=entry.entry_id,
                timestamp_ms=entry.timestamp_ms,
                actor=entry.actor,
                event_type=entry.event_type,
                parent_ids=entry.parent_ids,
                payload_digest=entry.payload_digest,
                metadata=entry.metadata,
                prev_hash=entry.prev_hash,
            )
            if recomputed != entry.entry_hash:
                return ChainVerificationResult(
                    valid=False,
                    checked_entries=idx,
                    error=f"entry_hash mismatch at seq={idx}",
                    broken_at_seq=idx,
                )
            seen_ids[entry.entry_id] = idx
            expected_prev = entry.entry_hash

        return ChainVerificationResult(
            valid=True,
            checked_entries=len(self._entries),
        )

    def trace_ancestors(self, entry_id: str) -> list[LedgerEntry]:
        if entry_id not in self._index_by_id:
            raise KeyError(f"Unknown entry_id: '{entry_id}'")
        target = self._entries[self._index_by_id[entry_id]]
        visited: set[str] = set()
        queue: deque[str] = deque(target.parent_ids)

        while queue:
            pid = queue.popleft()
            if pid in visited:
                continue
            visited.add(pid)
            parent_entry = self._entries[self._index_by_id[pid]]
            for grand_pid in parent_entry.parent_ids:
                if grand_pid not in visited:
                    queue.append(grand_pid)

        ancestors = [self._entries[self._index_by_id[eid]] for eid in visited]
        ancestors.sort(key=lambda e: e.seq)
        return ancestors
