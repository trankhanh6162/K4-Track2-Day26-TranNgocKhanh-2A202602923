# TASK 2 · PROSECUTE — `eval/prosecute.py`

> **Không chỉ ra được thì không có sát thương.** Một đòn tấn công của bạn dù trúng đến đâu, nếu
> đối thủ không nêu được bằng chứng thì trọng tài không chấm điểm gì cả. Và ngược lại: khi BẠN là
> bên cáo buộc, việc bạn phải làm không phải là "tìm ra lỗi" mà là **chứng minh nó, đúng sự kiện,
> đúng lớp lỗi, trong ngân sách 4 cáo buộc**.
>
> *No claim, no damage. When YOU are the prosecutor, the job is not "find a defect" — it is proving
> one, against the right event, under the right class, inside a 4-claim budget.*

This is Task 2. Your gateway (`agent/gateway.py`) is what your infrastructure **enforces**. This
file is what you can **prove** about somebody else's. You will receive the opponent's authoritative
L1 gateway trace (CONTRACTS.md §5.4 — their events only, `own_telemetry` stripped, their final
`answer` included) and file claims against it.

```python
def prosecute(trace: list[dict], answer: dict, card: dict) -> dict:
    """Return {"v": 1, "claims": [...]}. SYNCHRONOUS, no I/O, no network, 5 s deadline."""
```

## Individual Prosecutor

The current implementation supersedes the historical starter tutorial below.
Implementation changes are confined to `eval/`. No kit, bot, fixture, or public
test code is modified by this implementation.

Implemented trace-only predicates:

- `enforcement_failure`: follows the frozen deterministic referee contract:
  an authoritative arena mutation with both `applied=true` and
  `trigger_matched=true`, and its matching recorded `enforced.verdict_applied`
  differing from `deny`. Command plus enforced references are the sufficient
  proof. This includes A2A identity mutations and applied rewrites, without
  requiring a successful write, explicit act, or separate invariant/class match.
  Denied calls and mutations recorded as repaired (`applied=false`) or unmatched
  abstain. Explicit non-denial defense cards also abstain, consistent with spar;
  an absent defense annotation does not override the frozen predicate. `observed`
  describes the actual verdict, including `rewrite`, rather than assuming forward.
- `write_violation`: executed, forwarded known write tools with explicit missing
  canonical headers, or a repeated key within this exchange. Both writes are cited
  for reuse. Sparse command headers and repaired calls abstain.
- `protocol_misuse`: affirmative absent/expired lease evidence for executed
  `slides.get_frame`, or a cited partial result without a later same-tool continuation.
  Any later continuation command conservatively suppresses that partial-result claim.
- `fabricated_citation`: final trace answer cites a page never returned in this
  exchange, either in result anchors or a successful row's anchor field.
  Envelope/row inconsistencies abstain rather than accusing an invented citation.
  Matching ignores spans and permits omitted citation revisions as replica-agnostic.
- `authority_exceeded`: successful forwarded writes outside an explicitly recorded
  act or scope. `defender` is never assumed to be the learner identity.
- `privacy_leak`: explicitly marked private Note/Learner row text appears in the
  final trace answer with at least 40 contiguous normalized characters in common.
  Rows without unambiguous private-source identity are ignored.
- `wasteful`: executed tools whose results confirm deprecation and a supported
  successor, a cost subset
  of at most four calls that itself exceeds the referee's 11-credit round allowance,
  or consecutive identical failed calls exceeding the error's retry tolerance.
  Headers and leases are included in retry identity; successful or repaired calls
  break the chain. `unavailable` permits one unchanged retry. A specific failed
  retry takes precedence over an aggregate cost claim in the same family.
  Aggregate cost claims require matching explicit round numbers on the command
  and cited tool-call events; missing or conflicting round metadata abstains,
  rather than pooling all unlabelled calls under a synthetic round. Sparse spar
  traces therefore do not trigger a speculative overspending allegation.

Every implemented hook is wired into `ProsecutionBudget`. Claims use at most four
references and 400 argument characters, at most four claims and one per family.
Duplicate minimum-event causal references are suppressed. Processing is deterministic,
does not mutate inputs, and performs no I/O, network calls, or clock reads inside
`prosecute`. Trace answer events, not uncorroborated caller prose, ground answer claims.

### Verification And Limits

```bash
.venv/Scripts/python.exe -m pytest tests/test_prosecute.py -q
.venv/Scripts/python.exe -m pytest tests -q
.venv/Scripts/python.exe -m eval.prosecute
.venv/Scripts/python.exe -X utf8 spar.py --bot operator --as prosecutor --rounds 10 --seed 3
```

Use the provided suite and `kit.referee.verify.verify_claims` to check the
prosecutor against the fixture traces. The authored label scorer and actual
verifier can disagree on additional violations, as documented below.

Final conformance was checked with `make test` on WSL Ubuntu, Python 3.12.3:
4609 passed, 7 skipped, no failures. The public prosecution suite has 41
passing tests; authored-fixture precision is 1.0, recall is 0.353, and no
claims are false, unproven, or rejected by the local label scorer. Native
Windows still cannot run the kit's `msvcrt.open` probe; use the Unix test
environment rather than changing protected kit sources.

Step 7 self-check, Adversary / prosecutor / seed 1: 12 verified claims,
0 false, 0 pending, and 0 recoil over the eight rounds played (21-0 result).
This is the unmodified spar runner's local result, not a live-arena guarantee.
In-memory regression checks retain overspending detection with explicit matching
round metadata and abstain for missing/conflicting rounds. The public 41-test
prosecution suite and full 4609-test passing suite remain unchanged.

The eight semantic classes remain abstaining hooks. `wrong_answer` and `stale_read`
need world truth/drift not supplied through the trace-only entry point; two replica
anchors alone do not prove drift. The installed corpus at `kit/world/df8c55dabb35`
enables spar, but this prosecutor does not load or memorize it. World truth remains
arena-only, and no world file is read inside `prosecute`.
Privacy verification still needs the referee's seeded private world data: explicit
trace private rows support an argument, but the real verifier returns `unproven`
without world context. Cross-exchange idempotency reuse, unrecorded identity/scopes,
registry authenticity, body-mask semantic inference, and cost totals that cannot be
proved with four references are deliberately not guessed.

The authored labels and actual verifier do not always agree. The prosecutor
uses a conservative evidence policy: a returned row anchor suppresses a fabrication
claim, and tool deprecation needs explicit result metadata. This may miss some
verifier-detectable violations, but avoids accusing an agent for inconsistent
envelopes or sparse telemetry. No fixture identity, label, or memorized answer is
used by the decision logic. Both enforcement fixtures use the authoritative
matched applied mutations and command/enforced proof required by the contract.

Enforcement recall is 1.0 on both authored enforcement fixtures. Missed protocol
claims can share family A with the heavier enforcement claim, so the
one-per-family budget intentionally keeps enforcement. `-X utf8` avoids the
Windows terminal's CP1252 failure when
spar prints its Unicode report. Spar's canned trace and class-level scoring are
practice feedback, not a substitute for the actual verifier regressions.

The remaining sections describe the original starter and its scoring utilities.

## Starter Utilities

| Piece | What it does |
|---|---|
| `RUBRIC` / `family_of` / `weight_of` | The 17 classes, 5 families, weights — read from the vendored `kit/referee/rubric.py` once it lands, a local fallback copy until then. Same numbers either way. |
| `evt_ref` / `span_ref` / `anchor_ref` | The three evidence-ref grammars: `"evt:0412"` \| `"answer.span:3"` \| `"anchor:Frame:…"`. |
| `group_calls(trace)` | Buckets the L1 trace into per-`command` groups (`command`/`decision`/`enforced`/`tool_call`/`tool_result`/`mutations`) — the correlation almost every detector needs. |
| `split_sentences(text)` | The exact `answer.span:N` split. |
| `ProsecutionBudget` | A claim accumulator. `try_add(...)` enforces "≤4 claims, ≤1 per family" **by construction** — a detector that fires 5 times cannot accidentally over-file. Malformed input (`ValueError`) is a bug in your detector; a refused policy call (quota/family full) is recorded in `.dropped`, not an error. |
| `detect_enforcement_failure` | **The one competently-implemented detector.** Read it before writing your own — it is the template. |
| 16 named `_hook_*` stubs | One per remaining class, each a `return []` with a docstring naming exactly what CONTRACTS.md §6.4 (or the class's own definition, for the 8 adjudicated classes) says it needs. |
| `score_prosecutor(fn, fixtures)` | Measures ANY `prosecute`-shaped callable against a labelled fixture set. Run it against your own work before you ever point it at an opponent. |

## Why only one detector ships

`enforcement_failure` (weight **10**, the heaviest class) is also the most mechanical: CONTRACTS.md
§6.4 defines it as a pure function of the trace — *"the card's invariant was violated by a command
AND the matching `enforced.verdict_applied != 'deny'`"* — no text to read, no judgement call. Study
`detect_enforcement_failure`'s shape (group calls → scan for the predicate → cite the command +
`enforced` pair together) and reuse it. The 9 deterministic classes (CONTRACTS.md §6.3) are all
reachable this way; the 8 adjudicated classes (`ungrounded`, `hallucination`, `guardrail_breach`,
`unflagged_conflict`, `incoherent`, `overreach`, `non_responsive`, `unsupported_precision`) need
reading the answer's actual meaning — a real referee sends those to one blind model call
(`referee/adjudicate.py`, arena-only); your own detector can still flag a plausible instance and let
the claim's `argument` make the case.

## Developing your own detector

1. Pick a stub in `_HOOKS` (say `_hook_wasteful`). Read its docstring — it names the CONTRACTS.md
   rule it must implement, and honestly says what a trace-only prosecutor can and cannot reach.
2. Implement it returning `[(evidence_refs, argument), ...]`, same shape as
   `detect_enforcement_failure`.
3. Wire it into `prosecute()`'s loop (add its calls to `budget.try_add(...)`, same pattern as the
   `enforcement_failure` block above the loop).
4. Rerun `score_prosecutor` and watch your `recall` for that class move off 0.0 — and watch
   `false_claim_rate` and `precision` to make sure you did not trade recall for false claims.

```bash
python -m eval.prosecute            # scores the starter against fixtures/prosecution/labelled/
python -m pytest tests/test_prosecute.py -v
```

## `score_prosecutor` — measure yourself before a duel does

```python
from eval.prosecute import prosecute, score_prosecutor, load_fixtures

report = score_prosecutor(prosecute, load_fixtures())
```

Returns `{"precision", "recall", "f1", "false_claim_rate", "per_class": {...}, ...}`. It is a
**local, deterministic approximation** of the real referee's gate 1 (CONTRACTS.md §6.1–6.2), scored
against each fixture's authored ground truth rather than a live detector run or a model call — this
kit has no model access at all (zero-key, `MockBroker` only), so the 8 adjudicated classes are
approximated the same evidence-matching way as the 9 deterministic ones. It is not a promise of the
exact number the real referee will hand you, but the failure shapes it catches are the real ones.

**Definitions, all 0.0 on a zero denominator (never a crash):**

| Metric | Formula | Reads as |
|---|---|---|
| `precision` | `verified / adjudicated` | of the claims that were legitimate enough to be judged, how many actually proved what they claimed |
| `recall` | `verified / (total real defects across the fixture set)` | of everything actually wrong out there, how much did you both find AND cite correctly |
| `false_claim_rate` | `false / adjudicated` | the number that maps straight onto the `-0.8 × weight` penalty below |
| `f1` | harmonic mean of precision/recall | one number if you need one |

`adjudicated` excludes `rejected` claims (schema-invalid, over quota, or a duplicate — those are a
bug in your code, not a measurement of detection quality, but they are still counted and reported).
An `unproven` claim counts toward neither precision's nor recall's numerator — CONTRACTS.md §6.2
pays it exactly 0 either way, so this mirrors the real economics.

Running the starter (which implements exactly 1 of 17 classes) prints roughly:

```
precision: 1.000   recall: 0.059   f1: 0.111   false_claim_rate: 0.000
```

**That shape is correct, not a bug to fix**: perfect precision (it never guesses wrong when it does
file) and low recall (16 of 17 classes are still stubs). If your own numbers ever show HIGH recall
before you've implemented anything, something is wrong with your changes — check you did not
accidentally turn a stub into something that always fires.

## The fixture set — `fixtures/prosecution/labelled/`

40 traces, generated by `fixtures/prosecution/build_fixtures.py` (deterministic — rerun it any time,
the output is byte-identical): all 17 classes with ≥2 traces each, 6 clean (no-defect) traces, and
**exactly one near-miss per class** — a trace where the defect is real but the *obvious*-looking
evidence doesn't actually show it, and the *real* evidence is somewhere else. That distinction is the
whole difference between `unproven` (0 damage, no penalty) and `verified` (`+weight`) — see
`tests/test_prosecute.py::test_naive_prosecutor_is_unproven_on_the_near_miss_fixture` for it made
concrete: a deliberately naive prosecutor (cites the *first* mutation-shaped event, verdict
unchecked) gets `verified` on the plain positive trace and `unproven` on its near-miss twin.

Full detail on how the fixtures were built and what "ground truth" means here:
`fixtures/prosecution/build_fixtures.py`'s module docstring.

## The economics — read this before you write a detector

CONTRACTS.md §6.2's outcome table: `verified` earns `+weight × round_scale`; `false` costs
`−0.8 × weight × round_scale`. Filing blind is +EV exactly when

```
p(verified) × weight  >  (1 − p(verified)) × 0.8 × weight
```

which rearranges to `p > 0.8 / 1.8 = 4/9 ≈ 44.4%` — and **`weight` cancels out of both sides**. The
break-even is **44.4% for every one of the 17 classes**, weight-10 `enforcement_failure` and
weight-3 `wasteful` alike. There is no weight to shop for.

Contrast a flat penalty (an earlier draft of this game's rule, never shipped): a flat `−4` makes
blind filing +EV whenever `p > 4/(weight+4)` — **28.6%** for a weight-10 class but **57.1%** for
weight-3 `wasteful`. Under that scheme, a rational prosecutor would shotgun the heavy classes and
stay quiet on the light ones. **Under the scheme this lab actually uses, that strategy does not
work** — every class costs the same conviction confidence to be worth filing. `eval.prosecute`'s
`__main__` block computes both numbers exactly (as `fractions.Fraction`, never a float) so this is
demonstrated, not just asserted; `tests/test_prosecute.py` checks it for all 17 classes under both
schemes.

**The practical rule: file what you can point at a specific event and defend, not what pays the
most if you happen to be right.**
