"""agent/gateway.py — YOUR control plane. CONTRACTS.md section 4, exactly.

READ agent/README.md FIRST — it maps all five files in this directory to what
each is scored on. This file is the one CONTRACTS.md calls "the trusted
envelope's untrusted half": every single MCP / A2A / DISCOVER command your
agent's model wants to make passes through `Gateway.decide` before it is
allowed to happen.

WHY THERE IS NO `execute()` METHOD ON `GatewayContext` (read this before you
go looking for one — there isn't one, and that is not an oversight)
----------------------------------------------------------------------------
CONTRACTS.md section 4's trusted envelope, reproduced here because it is the
one diagram worth memorising:

    [ trusted ]   loop emits a raw action line
         v
    [ trusted ]   INTERCEPT + CANONICALISE -> Command        (kit/loop/agent.py)
         v
    [ UNTRUSTED ] Gateway.decide(cmd) -> Decision             <- THIS FILE
         v
    [ trusted ]   ENFORCE: honour the Decision, meter it,
                  apply the active mutation, execute the
                  ToolCall or refuse it                       (the arena)
         v
    [ trusted ]   RECORD the authoritative L1 event, then
                  RENDER the Observation                      (the arena)
         v
    [ trusted ]   the model sees the Observation

`decide()` returns a *decision*, never a *result*. You cannot reach a tool
server, a file, a socket, or a clock from in here — there is nothing to
call. Two things follow from that, and both matter more than they look:

  1. YOUR TRACE CANNOT BE FORGED. Every `command` / `decision` / `enforced`
     / `tool_call` / `tool_result` L1 event (CONTRACTS.md 5.2) is written by
     the arena, from what the arena itself actually did — never from
     anything you claimed happened. A student gateway that wanted to lie
     about having blocked an attack ("I totally denied that, trust me")
     simply has no channel to lie through: the only thing you ever hand
     back is this one small `Decision` value, and the arena is the one that
     turns it into history.
  2. NOBODY CAN ACCUSE YOU OF A CALL YOU DID NOT AUTHORISE, either. Because
     `decide()` is the ONLY door a command can walk through on its way to
     actually running, a prosecutor's `enforcement_failure` claim against
     you has exactly one thing to point at: the `Decision` you returned for
     that specific `cmd_id`. There is no ambiguity about "maybe the loop
     called the tool directly" — CONTRACTS.md 4.2 removed that path on
     purpose, and kit/loop/agent.py's own module docstring names the same
     invariant from the other side (the loop never imports this module,
     never sees a `Decision`, never executes anything itself).

The cost of that guarantee is that this file is PURE: synchronous, no I/O,
no threads, no `sleep`, 250 ms wall-clock deadline (RULES.md section 3).
Raising anything, returning something that is not a valid `Decision`, or
missing the deadline is treated by the arena as a DENIED command PLUS a 2
credit penalty PLUS an `integrity` event that hands the prosecutor a free
`enforcement_failure` — CONTRACTS.md 4.1's charging table, reproduced in
agent/README.md's own table. Getting this file to just plainly return valid
`Decision` values, every time, is worth more than getting it clever.

IMPLEMENTED POLICY
----------------------------------------------------------------------------
ROUTE uses known tool identities and explicit anchor/header agreement, not
an invented fresh-replica heuristic. ADMIT checks visible negative identity
attestations, peer skills, audience, trace syntax, injection-bearing payloads
and live leases. AUTHORIZE uses ctx.act and scopes and requires retrieved
provenance for writes. BUDGET narrows wildcards/catalogs, bounds query rows,
and uses current credits with a round ceiling and future-round reserve.

spar supplies no history or live leases, so it cannot demonstrate successful
writes or get_frame admission. Its synthetic answers never enter this class.
The real mutation stack can modify results after this decision; no gateway
policy can certify those unseen results or retroactively redact an ANSWER.

ONE THING WORTH INTERNALISING BEFORE YOU WRITE YOUR FIRST REAL CHECK:
`verdict="deny"` costs the CALLER (your own team) **zero credits** —
CONTRACTS.md 4.1's charging table has exactly one $0 row, and it is this
one. Refusing to make a call you cannot justify is FREE. That makes
abstention a real strategy, not a luxury you can't afford: a `deny` you can
defend beats a `forward` you can't, every time a prosecutor is watching.

Stdlib only. No network, no randomness, no wall-clock reads, no sleeping —
none of that would even survive the kernel sandbox (CONTRACTS.md 12), but
the point is this file has no reason to want any of it in the first place.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import re
from typing import Any, Mapping, Protocol, runtime_checkable

# kit.mcp.types is a collaborator's file (workspace hard rule 2: import it,
# degrade gracefully). It is present as of this writing and is core, stable
# infrastructure (CONTRACTS.md 3.1) — but this module must still not fail to
# IMPORT if a concurrent edit ever breaks it transiently. When it is
# unavailable, `Decision.call` type-checking is skipped (not enforced), and
# `Gateway.decide` falls back to a minimal local dict-shaped stand-in so the
# rest of this file — everything that does not need a *real* ToolCall — still
# runs.
try:
    from kit.mcp.types import ToolCall, ToolResult
    _TOOLCALL_AVAILABLE = True
except ImportError:  # pragma: no cover - collaborator file
    ToolCall = Any  # type: ignore[assignment, misc]
    _TOOLCALL_AVAILABLE = False

# kit.loop.agent is also a collaborator's file, used only by this module's
# own __main__ demo (to build real Commands the same way the arena's trusted
# canonicaliser would) — never by decide() itself, which never touches the
# loop. Degraded the same way.
try:
    from kit.loop.agent import canonicalise_action as _canonicalise_action
except ImportError:  # pragma: no cover - collaborator file
    _canonicalise_action = None

from agent.telemetry import RecordingGatewayContext, Telemetry
from agent.guardrails import scan_for_injected_instructions
from agent.strategy import cheap_mask, successor_of, pick_replica
from kit.mcp.specs import TOOL_SPECS, A2A_PEERS
from kit.mcp.servers import _LOCAL_TOOL_SPECS
from kit.mcp.a2a import AGENT_CARDS, SKILL_ROUTES, admit_skill, parse_traceparent

_SPECS = {**_LOCAL_TOOL_SPECS, **TOOL_SPECS}


def _history_entry(entry: Any) -> tuple[Mapping, Mapping, Mapping]:
    """Read only supplied values, never arbitrary result methods or lazy I/O."""
    if not isinstance(entry, Mapping):
        return {}, {}, {}
    prior, decision, outcome = (entry.get(k) for k in ("command", "decision", "outcome"))
    if isinstance(prior, Command):
        prior = prior.to_dict()
    if isinstance(decision, Decision):
        decision = decision.to_dict()
    if _TOOLCALL_AVAILABLE and isinstance(outcome, ToolResult):
        outcome = outcome.to_dict()
    prior = prior if isinstance(prior, Mapping) else {}
    decision = decision if isinstance(decision, Mapping) else {}
    # A rewrite's executed call, not its original command, identifies the result.
    call = decision.get("call")
    if _TOOLCALL_AVAILABLE and isinstance(call, ToolCall):
        call = call.to_dict()
    if isinstance(call, Mapping) and decision.get("verdict") in ("forward", "rewrite"):
        prior = {**prior, **call}
    return prior, decision, outcome if isinstance(outcome, Mapping) else {}


def _error_code(outcome: Mapping) -> Any:
    error = outcome.get("error")
    return error.get("code") if isinstance(error, Mapping) else outcome.get("error_code")


def _operation(server: str, tool: str, args: Mapping) -> str:
    """Logical payload identity excludes response masks and transport keys."""
    # These are the arguments the supplied write handlers actually consume.
    names = {
        ("progress", "record_mastery"): ("anchor", "concept", "mastery_level"),
        ("content", "flag_stale_slide"): ("anchor",),
        ("content", "file_content_bug"): ("anchor", "description"),
        ("registry", "pin"): ("anchor",),
    }.get((server, tool), tuple(args))
    payload = {name: args[name] for name in names if name in args}
    if (server, tool) == ("progress", "record_mastery"):
        payload.setdefault("mastery_level", "practiced")
    return json.dumps([server, tool, payload], sort_keys=True, separators=(",", ":"), allow_nan=False)

__all__ = [
    "COMMAND_KINDS",
    "DECISION_VERDICTS",
    "Command",
    "Decision",
    "GatewayContext",
    "Gateway",
]

# CONTRACTS.md 4.1: `Command.kind` — "mcp" | "a2a" | "discover". An "answer"
# action is NEVER a Command (kit/loop/agent.py's own module docstring: "an
# answer is not a tool call routed to a server, so it never becomes a
# Command at all") — it is handled entirely by the loop/arena and never
# reaches `Gateway.decide`.
COMMAND_KINDS: frozenset[str] = frozenset({"mcp", "a2a", "discover"})

# CONTRACTS.md 4.1: `Decision.verdict` — the closed three-member set.
DECISION_VERDICTS: frozenset[str] = frozenset({"forward", "deny", "rewrite"})


@dataclass(frozen=True, slots=True)
class Command:
    """CONTRACTS.md 4.1, field for field — "canonicalised by the arena
    BEFORE the student sees it". You never build one of these from your own
    agent's raw text; the arena's canonicaliser (kit/loop/agent.py's
    `canonicalise_action`, run inside the trusted envelope) already did that
    work and minted `cmd_id` by the time `decide()` sees it. The
    `from_action_dict` classmethod below exists only so this file's own demo
    (and your local tests, if you write any) can build a realistic `Command`
    without duplicating the arena's canonicalisation logic."""

    cmd_id: str
    kind: str  # "mcp" | "a2a" | "discover" — see COMMAND_KINDS
    raw: str
    server: str
    tool: str
    args: dict
    fields: tuple[str, ...]
    headers: dict
    lease_id: str | None
    call_index: int

    def __post_init__(self) -> None:
        if not isinstance(self.cmd_id, str) or not self.cmd_id:
            raise ValueError(f"Command.cmd_id must be a non-empty str, got {self.cmd_id!r}")
        if self.kind not in COMMAND_KINDS:
            raise ValueError(f"Command.kind must be one of {sorted(COMMAND_KINDS)}, got {self.kind!r}")
        if not isinstance(self.server, str) or not self.server:
            raise ValueError(f"Command.server must be a non-empty str, got {self.server!r}")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError(f"Command.tool must be a non-empty str, got {self.tool!r}")
        if not isinstance(self.args, dict):
            raise ValueError(f"Command.args must be a dict, got {type(self.args).__name__}")
        if not isinstance(self.headers, dict):
            raise ValueError(f"Command.headers must be a dict, got {type(self.headers).__name__}")
        if (
            not isinstance(self.call_index, int)
            or isinstance(self.call_index, bool)
            or self.call_index < 0
        ):
            raise ValueError(f"Command.call_index must be a non-negative int, got {self.call_index!r}")

    @classmethod
    def from_action_dict(cls, action: Mapping[str, Any], *, cmd_id: str) -> "Command":
        """Build a `Command` from the dict shape `kit.loop.agent.canonicalise_action`
        returns (`kind, raw, server, tool, args, fields, headers, lease_id,
        call_index` — everything except the arena-minted `cmd_id`, supplied
        here as a keyword). Raises `ValueError` if `action["kind"] ==
        "answer"` — an answer is never a Command (see the module docstring).
        This is a convenience for tests/demos, not something the real arena
        calls: the trusted envelope mints `cmd_id` itself and constructs the
        real `Command` on its own side of the boundary."""
        kind = action.get("kind")
        if kind == "answer":
            raise ValueError(
                "an 'answer' action never becomes a Command (kit/loop/agent.py: "
                "\"an answer is not a tool call routed to a server\") — do not "
                "route it through Gateway.decide at all"
            )
        return cls(
            cmd_id=cmd_id,
            kind=kind,
            raw=action["raw"],
            server=action["server"],
            tool=action["tool"],
            args=dict(action.get("args", {})),
            fields=tuple(action.get("fields", ())),
            headers=dict(action.get("headers", {})),
            lease_id=action.get("lease_id"),
            call_index=action.get("call_index", 0),
        )

    def to_dict(self) -> dict:
        return {
            "cmd_id": self.cmd_id,
            "kind": self.kind,
            "raw": self.raw,
            "server": self.server,
            "tool": self.tool,
            "args": dict(self.args),
            "fields": list(self.fields),
            "headers": dict(self.headers),
            "lease_id": self.lease_id,
            "call_index": self.call_index,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """CONTRACTS.md 4.1, field for field.

    Validated strictly (`__post_init__`) because a *structurally* invalid
    `Decision` is charged exactly like a raised exception — CONTRACTS.md
    4.1's charging table: "malformed Decision (schema-invalid) -> 2 cr
    penalty, command denied." Failing loudly HERE, in your own process
    during development, is strictly better than discovering it live in a
    duel as an unexplained penalty.

    `verdict == "deny"` requires a non-empty `reason` (CONTRACTS.md 4.1:
    "required when verdict == 'deny'; shown in the combat log") and
    forbids `call` — a real denial has nothing left to carry out.
    `verdict` in `("forward", "rewrite")` requires `call` to be set — the
    arena executes exactly that `ToolCall`, nothing else, per the trusted
    envelope's whole point (see the module docstring)."""

    verdict: str  # "forward" | "deny" | "rewrite" — see DECISION_VERDICTS
    reason: str | None = None
    call: "ToolCall | None" = None
    quarantine: bool = False
    note: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in DECISION_VERDICTS:
            raise ValueError(
                f"Decision.verdict must be one of {sorted(DECISION_VERDICTS)}, got {self.verdict!r}"
            )
        if self.verdict == "deny":
            if not isinstance(self.reason, str) or not self.reason.strip():
                raise ValueError("Decision.verdict=='deny' requires a non-empty 'reason'")
            if self.call is not None:
                raise ValueError("Decision.verdict=='deny' must not carry a 'call' — there is nothing to run")
        else:  # forward | rewrite
            if self.call is None:
                raise ValueError(f"Decision.verdict=={self.verdict!r} requires 'call' to be set")
            if _TOOLCALL_AVAILABLE and not isinstance(self.call, ToolCall):
                raise ValueError(
                    f"Decision.call must be a kit.mcp.types.ToolCall instance, got {type(self.call).__name__}"
                )
        if not isinstance(self.quarantine, bool):
            raise ValueError(f"Decision.quarantine must be a bool, got {self.quarantine!r}")
        if self.note is not None and not isinstance(self.note, str):
            raise ValueError(f"Decision.note must be a str or None, got {self.note!r}")

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "call": self.call.to_dict() if self.call is not None and hasattr(self.call, "to_dict") else self.call,
            "quarantine": self.quarantine,
            "note": self.note,
        }


@runtime_checkable
class GatewayContext(Protocol):
    """CONTRACTS.md 4.2 — "read-only, arena-provided". Note what this is
    NOT: unlike `Command`/`Decision` above, CONTRACTS.md writes this as a
    plain `class`, not a `@dataclass(frozen=True, ...)`. That is a real
    signal, not an inconsistency — a `GatewayContext` is a LIVE VIEW the
    arena owns and updates as the duel actually progresses (credits get
    spent, rounds advance, leases mint and expire), not a frozen snapshot
    you receive once. This file therefore models it as a structural
    `Protocol`: the arena hands your `Gateway.__init__` some object shaped
    like this (see `agent/telemetry.py`'s `RecordingGatewayContext` for a
    concrete example your own tests/demos can build), and you read
    `self.ctx.<field>` fresh every time `decide()` runs — NEVER cache a
    context field into a local variable across calls; if you need memory
    that persists across the duel (a cache, a budget tracker, drift notes),
    keep it on YOUR OWN `Gateway` instance attributes instead (CONTRACTS.md
    4.3: "Gateway is instantiated once per duel... persists across the 10
    rounds").

    There is deliberately no `execute` method here — see the module
    docstring's "WHY THERE IS NO execute() METHOD" section. `emit` is the
    ONE thing you can do that has any side effect at all, and it writes to
    `own_telemetry` only: your own side, never scored, never shown to the
    opponent (`agent/telemetry.py` wraps it)."""

    act: str  # "learner:sv-0417" — WHOM YOU SERVE. Authority derives from this.
    sub: str  # "agent:vlearn-tutor" — what you are. NOT authority.
    scopes: frozenset[str]  # {"wiki.read"}; writes need "wiki.write:progress" etc.
    credits: int  # remaining this duel
    round: int
    call_index: int
    leases: tuple[str, ...]  # live lease ids, arena-tracked
    history: tuple[Mapping[str, Any], ...]  # YOUR OWN prior (Command, Decision, outcome) triples this duel

    def emit(self, name: str, **payload: Any) -> None: ...


class Gateway:
    """Per-duel command control plane; never executes calls or sees ANSWER."""

    def __init__(self, ctx: GatewayContext) -> None:
        self.ctx = ctx
        self._telemetry = Telemetry(ctx)

        self._denied_cmd_ids: set[str] = set()
        self._cards: dict[str, Any] = dict(AGENT_CARDS)
        self._rate_calls: dict[tuple[str, str], list[tuple[str, int]]] = {}
        self._write_keys: set[str] = set()
        self._writes: dict[str, tuple[str, int]] = {}
        self._write_barriers: dict[str, int] = {}
        self._retry_used: set[str] = set()
        self._round_start: tuple[int, int] | None = None

    def note_card(self, server: str, card: dict) -> None:
        """Arena callback: signed cards, or spar's registry admission attestation.

        This hook is not a command argument; never trust an argument's `verified`.
        """
        self._cards[server] = dict(card)

    def decide(self, cmd: Command) -> Decision:
        """Pure synchronous policy over visible command and arena context only."""
        if (len(cmd.args) > 64 or len(cmd.headers) > 32 or
                not isinstance(cmd.fields, (tuple, list)) or len(cmd.fields) > 32 or
                any(not isinstance(f, str) for f in cmd.fields) or
                any(not isinstance(k, str) for k in cmd.args) or
                (cmd.lease_id is not None and not isinstance(cmd.lease_id, str)) or
                any(isinstance(v, str) and len(v) > 65536 for v in cmd.args.values())):
            return self.deny(cmd, "oversized or malformed command payload")
        # ROUTE: identity is catalogued; a body cannot override transport routing.
        key = (cmd.server, cmd.tool)
        spec = _SPECS.get(key)
        if spec is None:
            return self.deny(cmd, "unknown server or tool")
        args = dict(cmd.args)
        try:
            if len(json.dumps(args, sort_keys=True, allow_nan=False)) > 65536:
                return self.deny(cmd, "oversized logical payload")
        except (TypeError, ValueError, RecursionError):
            return self.deny(cmd, "payload must be bounded JSON data")
        if (cmd.server in A2A_PEERS) != (cmd.kind == "a2a"):
            return self.deny(cmd, "command kind does not match peer transport")
        headers = {}
        for name, value in cmd.headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                return self.deny(cmd, "malformed transport header")
            name = name.lower()
            if name in headers or len(value) > 4096 or "\r" in value or "\n" in value:
                return self.deny(cmd, "ambiguous transport header")
            headers[name] = value
        if any(k in args for k in ("route", "_route", "replica", "mcp-replica")) or "x-mcp-body-route" in headers:
            return self.deny(cmd, "route belongs in the transport header, not the body")
        if headers.get("mcp-replica", "w") not in ("w", "c"):
            return self.deny(cmd, "unknown replica")
        anchor = args.get("anchor")
        if isinstance(anchor, str):
            match = re.fullmatch(r"(?:Frame|Deck|Section):[^/]+/(w|c)(?:/[^/#]+)?(?:#.*)?", anchor)
            if match:
                if "mcp-replica" in headers and headers["mcp-replica"] != match[1]:
                    return self.deny(cmd, "replica header contradicts explicit anchor")
                headers.setdefault("mcp-replica", match[1])
        if cmd.server == "slides":
            headers.setdefault("mcp-replica", pick_replica(
                path_id=args.get("path_id") if isinstance(args.get("path_id"), str) else None,
                known_drifting=False,
            ).replica)
        tool = cmd.tool
        successor = successor_of(*key)
        if successor is not None:
            _, tool = successor
            spec = _SPECS[successor]
        key = (cmd.server, tool)

        # ADMIT: spar exposes these negative attestations before the gateway.
        if headers.get("x-server-fingerprint") == "unvouched" or headers.get("x-card-signature") == "invalid":
            return self.deny(cmd, "identity explicitly failed registry admission")
        if args.get("peer_unverified"):
            return self.deny(cmd, "peer response is explicitly unverified")
        if cmd.server in A2A_PEERS:
            card = self._cards.get(cmd.server)
            skills = [s for s, route in SKILL_ROUTES.items() if route == key]
            if "skill" in args:
                skill = args["skill"]
                if not isinstance(skill, str) or SKILL_ROUTES.get(skill) != key:
                    return self.deny(cmd, "explicit skill does not match peer route")
                skills = [skill]
            if isinstance(card, Mapping) and "verified" in card:
                declared = card.get("skills")
                admitted = (card.get("name", cmd.server) == cmd.server and card.get("verified") is True and
                    isinstance(declared, (tuple, list)) and any(s in declared for s in skills))
            else:
                try:
                    admitted = card is not None and any(
                        (admission := admit_skill(card, s)).admitted and admission.peer == cmd.server for s in skills)
                except (TypeError, ValueError):
                    admitted = False
            if not admitted:
                return self.deny(cmd, "peer card or skill not admitted")
        aud = headers.get("aud")
        if aud is not None and aud not in (cmd.server, f"a2a:{cmd.server}" if cmd.server in A2A_PEERS else f"mcp:{cmd.server}"):
            return self.deny(cmd, "audience does not match this hop")
        if "traceparent" in headers:
            try:
                parse_traceparent(headers["traceparent"])
            except ValueError:
                return self.deny(cmd, "invalid traceparent")
        # Scan instruction-bearing payloads, not educational search queries.
        for name in ("note", "instruction", "instructions", "peer_answer"):
            text = args.get(name)
            if isinstance(text, str) and scan_for_injected_instructions(text).suspicious:
                return self.deny(cmd, "injected instruction in payload")
        if "catalog" in args and isinstance(args["catalog"], str) and len(args["catalog"]) > 1024:
            return self.deny(cmd, "unsolicited oversized catalog payload")
        if spec.needs_lease and (not cmd.lease_id or cmd.lease_id not in self.ctx.leases):
            return self.deny(cmd, "get_frame requires an arena-issued live lease")

        # AUTHORIZE: compare learner identities, never the agent's privileged sub.
        act = self.ctx.act
        own_id = act.split(":", 1)[-1] if isinstance(act, str) and act.startswith("learner:") else None
        for name, target in args.items():
            is_identity = name.lower() in ("learner", "learner_id", "act")
            is_learner_anchor = isinstance(target, str) and target.lower().startswith("learner:")
            if is_identity or is_learner_anchor:
                if not isinstance(target, str) or target not in (act, f"Learner:{own_id}", own_id) or own_id is None:
                    return self.deny(cmd, "target is not owned by ctx.act")
        scope = f"wiki.write:{cmd.server}" if spec.is_write else "wiki.read"
        if scope not in self.ctx.scopes:
            return self.deny(cmd, "required scope not granted to ctx.act")
        if key == ("progress", "record_mastery") and not anchor and args.get("learner"):
            # The raw server accepts learner as an alias, but HardMode keys
            # its retrieved provenance by args.anchor. Ownership was checked above.
            anchor = f"Learner:{own_id}"
            args["anchor"] = anchor
        if spec.is_write:
            if not all(headers.get(h) for h in spec.required_headers):
                return self.deny(cmd, "write requires If-Match and Idempotency-Key")
            if not isinstance(anchor, str) or not anchor:
                return self.deny(cmd, "write requires an explicit target anchor")
            if headers["idempotency-key"] in self._write_keys:
                return self.deny(cmd, "write key already authorized; reconcile before another operation")
            # History is documented as mappings of command/decision/outcome,
            # not a raw L1 trace. spar supplies none, so cannot authorize writes.
            etag = None
            provenance_index = -1
            operation = _operation(cmd.server, tool, args)
            failed_operations = {}
            for index, entry in enumerate(self.ctx.history):
                prior, prior_decision, outcome = _history_entry(entry)
                if prior_decision.get("verdict") == "deny":
                    continue
                prior_args = prior.get("args")
                prior_key = (prior.get("server"), prior.get("tool"))
                prior_headers = prior.get("headers")
                if (all(isinstance(k, str) for k in prior_key) and _SPECS.get(prior_key) and
                        _SPECS[prior_key].is_write and isinstance(prior_headers, Mapping) and
                        any(isinstance(k, str) and k.lower() == "idempotency-key" and
                            v == headers["idempotency-key"] for k, v in prior_headers.items())):
                    return self.deny(cmd, "write key already attempted")
                if not isinstance(prior_args, Mapping) or prior_args.get("anchor") != anchor:
                    continue
                if prior_key == ("registry", "provenance"):
                    etag = None
                    provenance_index = -1
                    if outcome.get("ok") is True:
                        rows = outcome.get("rows") or ()
                        etag = outcome.get("etag") or (rows[0].get("etag") if isinstance(rows, (list, tuple)) and rows and isinstance(rows[0], Mapping) else None)
                        provenance_index = index
                elif all(isinstance(k, str) for k in prior_key) and _SPECS.get(prior_key) and _SPECS[prior_key].is_write:
                    etag = None
                    provenance_index = -1
                    try:
                        prior_operation = _operation(*prior_key, prior_args)
                    except (TypeError, ValueError, RecursionError):
                        continue
                    # Opaque unavailable and absent outcomes cannot prove no write landed.
                    definitely_failed = outcome.get("ok") is False and _error_code(outcome) in (
                        "conflict", "precondition_missing", "unauthorized", "bad_request", "not_found",
                        "rate_limited", "lease_required", "lease_expired")
                    failed_operations[prior_operation] = (prior.get("cmd_id"), definitely_failed and
                        failed_operations.get(prior_operation, (None, True))[1])
            if not etag or etag != headers["if-match"]:
                return self.deny(cmd, "write lacks matching retrieved provenance")
            if provenance_index < self._write_barriers.get(anchor, -1):
                return self.deny(cmd, "write requires provenance newer than last authorized target write")
            previous = self._writes.get(operation)
            if previous is not None:
                failed_id, definitely_failed = failed_operations.get(operation, (None, False))
                if failed_id != previous[0] or not definitely_failed or provenance_index < previous[1]:
                    return self.deny(cmd, "logical write replay lacks definite failure and newer provenance")
            elif operation in failed_operations and not failed_operations[operation][1]:
                return self.deny(cmd, "logical write already attempted with successful or unknown outcome")

        # BUDGET: price real masks; bound query rows rather than assuming one.
        fields = tuple(cmd.fields)
        if key == ("slides", "query"):
            try:
                limit = int(args.get("limit", 1))
            except (TypeError, ValueError, OverflowError):
                return self.deny(cmd, "invalid query limit")
            if isinstance(args.get("limit"), (bool, float)) or limit < 1:
                return self.deny(cmd, "invalid query limit")
            args["limit"] = min(limit, 3)
            if cmd.tool == "search":
                fields = tuple("body" if f == "snippet" else "title" if f == "anchor" else f for f in fields)
        if key in (("registry", "list_servers"), ("glossary", "list_terms")) and fields in ((), ("*",)):
            fields = cheap_mask(*key, ("name",) if cmd.server == "registry" else ("term",))
        elif fields == ("*",):
            fields = cheap_mask(*key, spec.default_fields)
        if any(f not in spec.all_fields for f in fields):
            return self.deny(cmd, "unknown field mask for this tool")
        effective = fields or spec.default_fields
        n_rows = args["limit"] if key == ("slides", "query") else 0
        estimate = spec.base + sum(spec.field_weight[f] for f in set(effective)) + spec.row_weight * n_rows
        rnd, credits = self.ctx.round, self.ctx.credits
        if self._round_start is None or self._round_start[0] != rnd:
            self._round_start = (rnd, credits)
        spent = max(0, self._round_start[1] - credits)
        reserve = max(0, 10 - rnd) * 5
        if (estimate > credits - reserve or spent + estimate > 11) and tuple(cmd.fields) in ((), ("*",)) and effective:
            # No explicit answer fields may be discarded to make a call affordable.
            fields = cheap_mask(*key, tuple(f for f in effective if spec.field_weight[f] == 0))
            if fields:
                estimate = spec.base + spec.row_weight * n_rows
        if estimate > credits - reserve or spent + estimate > 11:
            return self.deny(cmd, "call exceeds remaining credits or sustainable round budget")
        routed = replace(cmd, tool=tool, args=args, fields=fields, headers=headers)
        retry_id = None
        failures = 0
        for entry in reversed(self.ctx.history):
            prior, prior_decision, outcome = _history_entry(entry)
            if prior_decision.get("verdict") == "deny":
                continue
            prior_key = (prior.get("server"), prior.get("tool"))
            prior_args = prior.get("args")
            if not isinstance(prior_args, Mapping):
                continue
            prior_args = dict(prior_args)
            prior_fields = prior.get("fields", ())
            if not isinstance(prior_fields, (tuple, list)):
                continue
            if prior_key in (("slides", "query"), ("slides", "search")):
                if prior_key == ("slides", "search"):
                    prior_fields = tuple("body" if f == "snippet" else "title" if f == "anchor" else f for f in prior_fields)
                prior_key = ("slides", "query")
                prior_args.setdefault("limit", 1)
            if prior_key != key or prior_args != args:
                continue
            prior_headers = prior.get("headers", {})
            if not isinstance(prior_headers, Mapping):
                continue
            prior_headers = {k.lower(): v for k, v in prior_headers.items() if isinstance(k, str)}
            if cmd.server == "slides":
                prior_anchor = prior_args.get("anchor")
                prior_match = re.fullmatch(r"(?:Frame|Deck|Section):[^/]+/(w|c)(?:/[^/#]+)?(?:#.*)?", prior_anchor) if isinstance(prior_anchor, str) else None
                prior_headers.setdefault("mcp-replica", prior_match[1] if prior_match else "w")
            condition_headers = ("mcp-replica", "aud", "x-server-fingerprint", "x-card-signature")
            if (any(not isinstance(f, str) for f in prior_fields) or
                    any(prior_headers.get(h) != headers.get(h) for h in condition_headers) or
                    sorted(prior_fields or spec.default_fields) != sorted(fields or spec.default_fields) or
                    prior.get("lease_id") != cmd.lease_id):
                continue
            if outcome.get("ok") is not False:
                break
            if spec.is_write:
                break  # Writes have the stronger provenance/replay gate above.
            if _error_code(outcome) != "unavailable":
                return self.deny(cmd, "unchanged call previously failed definitively; revise its conditions")
            failures += 1
            retry_id = prior.get("cmd_id")
            if failures > 1 or not isinstance(retry_id, str) or retry_id in self._retry_used:
                return self.deny(cmd, "unchanged unavailable read retry already exhausted")
        if spec.rate_limit:
            allowed, window = spec.rate_limit
            unavailable_ids = set()
            for entry in self.ctx.history:
                prior, prior_decision, outcome = _history_entry(entry)
                prior_id = prior.get("cmd_id")
                if (isinstance(prior_id, str) and prior_decision.get("verdict") != "deny" and
                        outcome.get("ok") is False and _error_code(outcome) == "unavailable"):
                    unavailable_ids.add(prior_id)
            # HardMode does not consume a rate slot for an opaque-killed call.
            recent = [(cid, r) for cid, r in self._rate_calls.get(key, [])
                      if r >= rnd - window + 1 and cid not in unavailable_ids]
            if len(recent) >= allowed:
                return self.deny(cmd, "tool rate window exhausted")
            self._rate_calls[key] = recent + [(cmd.cmd_id, rnd)]
        if spec.is_write:
            self._write_keys.add(headers["idempotency-key"])
            self._writes[operation] = (cmd.cmd_id, len(self.ctx.history))
            self._write_barriers[anchor] = len(self.ctx.history)
        if retry_id is not None:
            self._retry_used.add(retry_id)
        call = self._to_tool_call(routed)
        decision = Decision(verdict="rewrite" if routed != cmd else "forward", call=call)
        self._telemetry.decision_made(cmd, decision)
        return decision

    def deny(self, cmd: Command, reason: str) -> Decision:
        """Return a free denial without a call; log no private payloads."""
        self._denied_cmd_ids.add(cmd.cmd_id)
        decision = Decision(verdict="deny", reason=reason)
        self._telemetry.decision_made(cmd, decision)
        return decision

    def _to_tool_call(self, cmd: Command) -> "ToolCall":
        """`Command` -> the `ToolCall` (CONTRACTS.md 3.1) the arena will
        actually execute on a `forward`/`rewrite` verdict. When
        `kit.mcp.types` is unavailable (see the module-level import guard),
        falls back to a plain dict carrying the identical fields — `Decision`
        accepts it either way (the `ToolCall` isinstance check inside
        `Decision.__post_init__` only runs when the real class loaded)."""
        fields = {
            "server": cmd.server,
            "tool": cmd.tool,
            "args": dict(cmd.args),
            "fields": cmd.fields,
            "headers": dict(cmd.headers),
            "lease_id": cmd.lease_id,
            "call_index": cmd.call_index,
        }
        if _TOOLCALL_AVAILABLE:
            return ToolCall(**fields)
        return fields  # type: ignore[return-value]


if __name__ == "__main__":
    print("=== agent.gateway: Command / Decision validation ===\n")

    good_cmd = Command(
        cmd_id="cmd:0000",
        kind="mcp",
        raw="MCP slides.get_frame anchor=Frame:3f2a9c11/w/041 fields=title,body lease=lse_7f21",
        server="slides",
        tool="get_frame",
        args={"anchor": "Frame:3f2a9c11/w/041"},
        fields=("body", "title"),
        headers={},
        lease_id="lse_7f21",
        call_index=0,
    )
    print(f"  Command constructed: {good_cmd}")
    assert good_cmd.kind == "mcp"

    print("\n  Rejection demo (each must raise ValueError):")

    def _expect_value_error(label: str, fn) -> None:
        try:
            fn()
        except ValueError as exc:
            print(f"    [{label:38}] -> ValueError: {exc}")
        else:
            raise AssertionError(f"expected ValueError for case {label!r}")

    _expect_value_error("Command.kind == 'answer'", lambda: Command(
        cmd_id="cmd:0001", kind="answer", raw="x", server="slides", tool="get_frame",
        args={}, fields=(), headers={}, lease_id=None, call_index=0,
    ))
    _expect_value_error("Decision verdict='deny' with no reason", lambda: Decision(verdict="deny"))
    _expect_value_error(
        "Decision verdict='forward' with no call", lambda: Decision(verdict="forward")
    )
    _expect_value_error(
        "Decision verdict='deny' carrying a call",
        lambda: Decision(verdict="deny", reason="nope", call={"server": "x", "tool": "y"}),
    )
    _expect_value_error("Decision verdict='?' unknown", lambda: Decision(verdict="???"))

    print("\n=== Command.from_action_dict — real canonicaliser integration ===\n")
    if _canonicalise_action is None:
        print("  kit.loop.agent not importable yet — skipping the live canonicaliser demo")
        demo_commands: list[Command] = [good_cmd]
    else:
        raw_actions = [
            "MCP registry.provenance anchor=Frame:3f2a9c11/w/041 fields=etag",
            'MCP slides.query q="streamable http replaces http+sse" fields=title,body',
            "A2A curriculum-analyst.which_days_cover concept=Concept:streamable-http fields=anchor,course_day,track",
            "DISCOVER registry.list_servers fields=name",
        ]
        demo_commands = []
        for i, raw in enumerate(raw_actions):
            action = _canonicalise_action(raw, call_index=i)
            cmd = Command.from_action_dict(action, cmd_id=f"cmd:{i:04d}")
            print(f"  {raw!r}\n    -> {cmd.kind}: {cmd.server}.{cmd.tool} fields={cmd.fields}")
            demo_commands.append(cmd)
        assert {c.kind for c in demo_commands} == {"mcp", "a2a", "discover"}

        answer_action = _canonicalise_action(
            'ANSWER {"text": "day 26, track P2T2"}', call_index=None
        )
        try:
            Command.from_action_dict(answer_action, cmd_id="cmd:9999")
        except ValueError as exc:
            print(f"\n  an 'answer' action correctly refuses to become a Command: {exc}")
        else:
            raise AssertionError("expected ValueError for an 'answer' action")

    print("\n=== Gateway.decide — command policy ===\n")
    ctx = RecordingGatewayContext(
        act="learner:sv-0401",
        sub="agent:demo-team",
        scopes=frozenset({"wiki.read"}),
        credits=100,
        round=1,
        call_index=0,
        leases=(),
        history=(),
    )
    assert isinstance(ctx, GatewayContext), "RecordingGatewayContext must structurally satisfy GatewayContext"
    gw = Gateway(ctx)
    for cmd in demo_commands:
        decision = gw.decide(cmd)
        print(f"  decide({cmd.server}.{cmd.tool}) -> verdict={decision.verdict!r} quarantine={decision.quarantine}")
        assert decision.verdict in ("forward", "rewrite")
        assert decision.call is not None
        call_dict = decision.call.to_dict() if hasattr(decision.call, "to_dict") else decision.call
        assert call_dict["server"] == cmd.server
        assert call_dict["tool"] == cmd.tool

    print(f"\n=== Gateway.deny — free-abstention path ===\n")
    denial = gw.deny(demo_commands[0], reason="demo: withholding pending a fresher registry.provenance read")
    print(f"  gw.deny(...) -> verdict={denial.verdict!r} reason={denial.reason!r} call={denial.call!r}")
    assert denial.verdict == "deny"
    assert denial.call is None
    assert demo_commands[0].cmd_id in gw._denied_cmd_ids

    print(f"\n=== own_telemetry — recorded on YOUR side only, never shown to the opponent ===\n")
    print(f"  {len(ctx.events)} events recorded on this ctx this run:")
    for ev in ctx.events:
        print(f"    {ev['name']}: {sorted(ev['payload'].keys())}")
    assert len(ctx.events) >= len(demo_commands) + 1

    print("\n=== Four JOBS: in-memory regression scenarios ===")
    from time import perf_counter
    from kit.mcp.types import ToolResult
    from kit.mcp.specs import cost_of
    from kit.mcp.a2a import issue_card

    timings = []
    checks = 0

    def context(**kw):
        return RecordingGatewayContext(**{
            "act": "learner:sv-0401", "sub": "agent:demo", "credits": 100,
            "round": 1, "call_index": 0, "scopes": frozenset({"wiki.read", "wiki.write:progress", "wiki.write:content"}),
            "leases": ("live",), **kw})

    def command(server="glossary", tool="define", **kw):
        return Command(**{"cmd_id": "demo:call", "kind": "a2a" if server in A2A_PEERS else "mcp",
            "raw": "demo", "server": server, "tool": tool, "args": {"term": "example"},
            "fields": (), "headers": {}, "lease_id": None, "call_index": 0, **kw})

    def check(gateway, command, allowed=True):
        global checks
        start = perf_counter()
        decision = gateway.decide(command)
        timings.append(perf_counter() - start)
        assert (decision.verdict != "deny") == allowed, decision
        assert isinstance(decision, Decision)
        checks += 1
        return decision

    def history(command, outcome, decision=None):
        return {"command": command, "decision": decision or {}, "outcome": outcome}

    frame = "Frame:deadbeef/c/041"
    read = command("slides", "get_frame", args={"anchor": frame}, lease_id="live")
    g = Gateway(context())
    routed_read = check(g, read)
    assert routed_read.call.args["anchor"] == frame
    assert routed_read.call.headers["mcp-replica"] == "c"
    check(g, replace(read, headers={"mcp-replica": "w"}), False)
    check(g, replace(read, lease_id="invented"), False)
    g.ctx.leases = ()
    check(g, read, False)
    query = command("slides", "query", args={"q": "example"}, fields=("body", "title"))
    query_decision = check(Gateway(context()), query)
    assert query_decision.call.args == {"q": "example", "limit": 1}
    assert query_decision.call.fields == ("body", "title")
    search = replace(query, tool="search", fields=("anchor", "snippet"))
    assert check(Gateway(context()), search).call.fields == ("body", "title")
    check(Gateway(context()), replace(query, args={"q": "example", "limit": float("inf")}), False)
    check(Gateway(context()), replace(query, fields=("unknown",)), False)
    check(Gateway(context()), replace(query, args={"q": "example", "replica": "c"}), False)
    check(Gateway(context()), replace(query, args={"q": object()}), False)
    for peer, tool, skill in (("curriculum-analyst", "which_days_cover", "which_days_cover"),
                             ("citation-checker", "verify_source", "verify_source"),
                             ("roster", "lookup_learner", "who_enrolled")):
        peer_cmd = command(peer, tool, args={"skill": skill})
        check(Gateway(context()), peer_cmd)
        for invalid in ("invented", "", None, [], "define"):
            check(Gateway(context()), replace(peer_cmd, args={"skill": invalid}), False)
        check(Gateway(context()), replace(peer_cmd, kind="mcp"), False)
        check(Gateway(context()), replace(peer_cmd, headers={"aud": "a2a:other"}), False)
        forged = Gateway(context())
        forged.note_card(peer, {**AGENT_CARDS[peer].to_dict(), "signature": "forged"})
        check(forged, peer_cmd, False)
    check(Gateway(context()), replace(query, kind="a2a"), False)
    restricted = Gateway(context())
    restricted.note_card("roster", issue_card("roster", "a2a://roster", "0.3", ("role_of",)).to_dict())
    check(restricted, command("roster", "lookup_learner", args={"skill": "who_enrolled"}), False)
    check(restricted, command("roster", "lookup_learner", args={"skill": "role_of"}))
    restricted.note_card("roster", AGENT_CARDS["citation-checker"].to_dict())
    check(restricted, command("roster", "lookup_learner", args={"skill": "role_of"}), False)

    target = "Learner:sv-0401"
    prov = command("registry", "provenance", cmd_id="demo:provenance", args={"anchor": target})
    write = command("progress", "record_mastery", cmd_id="demo:write", args={"anchor": target, "concept": "Concept:one"},
                    headers={"if-match": "etag:1", "idempotency-key": "key:1"})
    for result in (ToolResult(ok=True, etag="etag:1"), {"ok": True, "rows": [{"etag": "etag:1"}]}):
        c = context(history=(history(prov, result),))
        g = Gateway(c)
        approved = check(g, write)
        check(g, replace(write, headers={"if-match": "etag:1", "idempotency-key": "key:2"}), False)
        different = replace(write, cmd_id="demo:different", args={"anchor": target, "concept": "Concept:two"},
                            headers={"if-match": "etag:1", "idempotency-key": "key:3"})
        check(g, different, False)  # Even a new payload needs a post-write read.
        c.history += (history(write, ToolResult(ok=True), approved), history(prov, result))
        check(g, different)
        check(g, replace(write, headers={"if-match": "etag:1", "idempotency-key": "key:4"}), False)
        c.history += (history(prov, result),)
        check(g, replace(write, args={**write.args, "mastery_level": "practiced", "unused": "not a new operation"},
                         fields=("mastery_level",), headers={"if-match": "etag:1", "idempotency-key": "key:5"}), False)
    for error in ("conflict", "unavailable", None):
        for flattened in (False, True):
            c = context(history=(history(prov, {"ok": True, "etag": "etag:1"}),))
            g = Gateway(c)
            approved = check(g, write)
            outcome = ({} if error is None else {"ok": False, **(
                {"error_code": error} if flattened else {"error": {"code": error}})})
            c.history += (history(write, outcome, approved),)
            retry = replace(write, cmd_id="demo:retry", headers={"if-match": "etag:1", "idempotency-key": "key:2"})
            check(g, retry, False)
            c.history += (history(prov, {"ok": True, "etag": "etag:1"}),)
            check(g, retry, error == "conflict")
            check(g, write, False)
    check(Gateway(context()), write, False)
    check(Gateway(context(history=(history(prov, {"ok": False, "error": {"code": "unavailable"}}),))), write, False)
    check(Gateway(context(scopes=frozenset({"wiki.read"}))), write, False)
    check(Gateway(context()), replace(write, args={"anchor": "Learner:other", "concept": "Concept:one"}), False)

    plain = command(cmd_id="demo:read")
    for outcome in (ToolResult(ok=False, error={"code": "unavailable"}),
                    {"ok": False, "error": {"code": "unavailable"}},
                    {"ok": False, "error_code": "unavailable"}):
        c = context(history=(history(plain, outcome),))
        g = Gateway(c)
        retry = replace(plain, cmd_id="demo:retry", call_index=1)
        approved = check(g, retry)
        check(g, retry, False)  # No outcome yet: cannot authorize the retry twice.
        c.history += (history(retry, outcome, approved),)
        check(g, replace(retry, cmd_id="demo:third", call_index=2), False)
    for code in ("bad_request", "not_found", "unauthorized", "conflict", "rate_limited"):
        c = context(history=(history(plain, {"ok": False, "error_code": code}),))
        g = Gateway(c)
        check(g, plain, False)
        check(g, replace(plain, args={"term": "revised"}))
    c = context(history=(history(query, {"ok": False, "error_code": "bad_request"}),))
    check(Gateway(c), query, False)  # Default limit/header normalization is not a condition change.
    c = context(history=(history(plain, {"ok": False, "error_code": "not_found"}),))
    check(Gateway(c), replace(plain, headers={"traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01"}), False)
    class LazyResult:
        def to_dict(self):
            raise AssertionError("must never invoke arbitrary outcome methods")
    check(Gateway(context(history=(None, {"command": []}, history(prov, LazyResult())))), write, False)

    low = Gateway(context(round=10, credits=2))
    narrowed = check(low, read)
    assert "body" not in narrowed.call.fields and "title" in narrowed.call.fields
    check(Gateway(context(round=10, credits=2)), replace(read, fields=("body", "title")), False)
    check(Gateway(context(round=10, credits=0)), plain, False)
    check(Gateway(context()), command("research", "search", args={"q": "example"}, fields=("title", "url")))
    rates = Gateway(context())
    catalog = command("registry", "list_servers", args={})
    assert check(rates, catalog).call.fields == ("name",)
    check(rates, catalog, False)
    rates = Gateway(context())
    approved = check(rates, catalog)
    rates.ctx.history = (history(catalog, {"ok": False, "error_code": "unavailable"}, approved),)
    check(rates, replace(catalog, cmd_id="demo:catalog-retry", call_index=1))
    check(rates, replace(catalog, cmd_id="demo:catalog-third", call_index=2), False)
    verifier = command("citation-checker", "verify_source", args={}, fields=("confidence",))
    rates = Gateway(context())
    check(rates, verifier)
    check(rates, verifier)
    rates.ctx.round = 3
    check(rates, verifier, False)
    rates.ctx.round = 4
    check(rates, verifier)

    c = context()
    g = Gateway(c)
    for rnd in range(1, 11):
        c.round = rnd
        c.leases = ("live",)
        start_credits = c.credits
        for cmd in (query, replace(read, args={"anchor": "Frame:deadbeef/w/001"}), prov):
            decision = check(g, cmd)
            c.credits -= cost_of(decision.call, 1)
        assert start_credits - c.credits == 9
    assert c.credits == 10
    c = context()
    g = Gateway(c)
    check(g, plain)
    c.credits = 89
    check(g, plain, False)  # Live spend, not estimated accumulated spend.
    assert max(timings) < 0.250
    print(f"  {checks} decision assertions passed; ten rounds cost 90cr, 10cr left")
    print(f"  max decide wall time: {max(timings) * 1000:.3f}ms (measured outside decide)")
    print("\nAll agent/gateway.py demos passed.")
