"""Scheduled cruise daemon for ossuary — `ossuary watch`.

Cruise (`ossuary cruise`) is a single-invocation re-scan + diff: run once, diff
against the last saved state, print, exit. `watch` closes the gap between that
one-shot scan and *continuous monitoring*: it runs cruise on a fixed interval,
emitting a human-readable diff summary each pass.

Persistent, recurring recon is the standard for hunters working long-running
programs — ports opening on new IPs, version bumps, and service removals are
all high-signal moments that a one-shot scan only catches if you remember to
re-run it. `watch` automates the remembering.

Worker decision (POST_V01 Rank 5): the spec suggested `apscheduler`. A fixed
single-interval loop does not need a cron-grade scheduler — that dependency adds
install surface and process-management complexity out of proportion to the
feature. Instead the loop is a plain `time.sleep`-driven cycle with the clock,
the sleeper, and the cruise call injected as seams, so the whole daemon is
exercised offline by the test suite with zero wall-clock waiting and no new
dependency. Slack/file notification reuses the already-present `httpx`.

Notification sinks (`--notify`):

    file:<path>     append each interval's summary to a file (newline-delimited)
    slack:<webhook> POST each interval's summary to a Slack incoming webhook

Both are optional and may be combined. Slack webhook URLs are accepted only on
the command line / sink spec and are never written to the engagement DB.
"""

from __future__ import annotations

import json
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import cruise as cruise_mod

# Human-friendly duration unit -> seconds. Used to parse `--interval 4h`.
_UNIT_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}


def parse_interval(spec: str) -> int:
    """Parse a human duration spec (`4h`, `30m`, `90s`, `1d`, `300`) to seconds.

    A bare integer is treated as seconds. A trailing unit suffix (s/m/h/d) is
    multiplied accordingly. Raises ValueError on anything else so a typo fails
    loudly at startup rather than silently scheduling a nonsense interval.
    """
    text = spec.strip().lower()
    if not text:
        raise ValueError("interval must not be empty")

    if text[-1] in _UNIT_SECONDS:
        number, unit = text[:-1], text[-1]
    else:
        number, unit = text, "s"

    try:
        value = int(number)
    except ValueError:
        raise ValueError(
            f"invalid interval {spec!r}: expected an integer optionally "
            "suffixed with s/m/h/d (e.g. 4h, 30m, 90s, 300)"
        ) from None

    if value <= 0:
        raise ValueError(f"interval must be positive, got {spec!r}")

    return value * _UNIT_SECONDS[unit]


def summarise_diff(diff: dict, *, iteration: int, when: str) -> str:
    """Render a cruise diff dict as a compact one-block human summary.

    The header line carries the iteration number, timestamp, and counts; the
    body lists each added / removed / changed service and any tag changes. A
    fully-quiet interval (nothing moved) is reported explicitly so an operator
    watching the log knows the daemon is alive and the surface is stable.
    """
    added = diff.get("added", [])
    removed = diff.get("removed", [])
    changed = diff.get("changed", [])
    tag_changes = diff.get("tag_changes", [])

    lines = [
        f"[cruise #{iteration} @ {when}] "
        f"{len(added)} added, {len(removed)} removed, "
        f"{len(changed)} changed, {len(tag_changes)} tag change(s)"
    ]

    for entry in added:
        detail = entry.get("detail", {})
        lines.append(f"  + {entry['service']}  {_fmt_service(detail)}")
    for entry in removed:
        detail = entry.get("detail", {})
        lines.append(f"  - {entry['service']}  {_fmt_service(detail)}")
    for entry in changed:
        before = _fmt_service(entry.get("from", {}))
        after = _fmt_service(entry.get("to", {}))
        lines.append(f"  ~ {entry['service']}  {before} -> {after}")
    for entry in tag_changes:
        bits = []
        if entry.get("added"):
            bits.append("+" + ",".join(entry["added"]))
        if entry.get("removed"):
            bits.append("-" + ",".join(entry["removed"]))
        lines.append(f"  # {entry['asset']}  tags {' '.join(bits)}")

    if not (added or removed or changed or tag_changes):
        lines.append("  (no changes)")

    return "\n".join(lines)


def _fmt_service(detail: dict) -> str:
    """Format a service detail dict (name/product/version) compactly."""
    product = detail.get("product") or detail.get("name") or "?"
    version = detail.get("version")
    return f"{product} {version}" if version else str(product)


def diff_has_changes(diff: dict) -> bool:
    """True if a cruise diff carries any added/removed/changed/tag change."""
    return bool(
        diff.get("added")
        or diff.get("removed")
        or diff.get("changed")
        or diff.get("tag_changes")
    )


# --------------------------------------------------------------------------
# Notification sinks
# --------------------------------------------------------------------------


@dataclass
class FileSink:
    """Append-to-file notification sink.

    Each interval's summary is appended as a newline-terminated block. Suitable
    for `tail -f`-ing the diff history or feeding a downstream log shipper.
    """

    path: Path

    def send(self, summary: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(summary + "\n")


@dataclass
class SlackSink:
    """Slack incoming-webhook notification sink.

    Posts each interval's summary as a Slack message. The webhook URL lives only
    here (from the CLI sink spec) and is never persisted to the engagement DB.
    Network/HTTP failures are surfaced to the caller, which logs and continues —
    a flaky webhook must not kill the watch loop.
    """

    webhook: str
    timeout: float = 10.0
    _client_factory: Callable[[], httpx.Client] | None = None

    def send(self, summary: str) -> None:
        factory = self._client_factory or (lambda: httpx.Client(timeout=self.timeout))
        with factory() as client:
            response = client.post(self.webhook, json={"text": summary})
            response.raise_for_status()


def parse_notify(spec: str) -> FileSink | SlackSink:
    """Build a notification sink from a `<kind>:<target>` spec string.

    Supported kinds: `file:<path>` and `slack:<webhook-url>`. The split is on the
    first colon only, so Slack URLs (which contain `https://`) survive intact.
    Raises ValueError on an unknown kind or a missing target.
    """
    if ":" not in spec:
        raise ValueError(
            f"invalid --notify {spec!r}: expected file:<path> or slack:<webhook>"
        )
    kind, _, target = spec.partition(":")
    kind = kind.strip().lower()
    target = target.strip()
    if not target:
        raise ValueError(f"invalid --notify {spec!r}: empty target after {kind!r}")

    if kind == "file":
        return FileSink(Path(target))
    if kind == "slack":
        return SlackSink(target)
    raise ValueError(
        f"unknown --notify kind {kind!r} (valid: file, slack)"
    )


# --------------------------------------------------------------------------
# The watch loop
# --------------------------------------------------------------------------


@dataclass
class WatchConfig:
    """Resolved configuration for one `watch` run.

    `iterations` of None means "run forever" (until SIGTERM/SIGINT); a positive
    integer bounds the loop (used by `--iterations`/`--once` and by tests). The
    `cruise_fn`, `sleeper`, `clock`, and `printer` are injectable seams so the
    daemon runs in tests with no wall-clock waiting and no real scan.
    """

    db_path: str | Path
    interval_seconds: int
    sinks: list = field(default_factory=list)
    iterations: int | None = None
    quiet_when_unchanged: bool = False
    # cruise_fn is resolved lazily (None -> cruise_mod.cruise at call time) so
    # the default tracks any monkeypatch of the cruise module rather than being
    # frozen at class-definition time.
    cruise_fn: Callable[[str | Path], dict] | None = None
    sleeper: Callable[[float], None] = time.sleep
    clock: Callable[[], str] = lambda: time.strftime("%Y-%m-%dT%H:%M:%S")
    printer: Callable[[str], None] = print

    def resolve_cruise(self) -> Callable[[str | Path], dict]:
        """Return the cruise callable, defaulting to the module's `cruise`."""
        return self.cruise_fn if self.cruise_fn is not None else cruise_mod.cruise


class _Stopper:
    """Tracks a cooperative stop request from SIGTERM/SIGINT.

    The watch loop checks `requested` between intervals and after each cruise so
    a signal received mid-sleep results in a clean exit rather than an abrupt
    kill — the in-flight cruise has already committed its snapshot by then.
    """

    def __init__(self) -> None:
        self.requested = False

    def request(self, *_: object) -> None:
        self.requested = True


def watch(config: WatchConfig) -> int:
    """Run cruise on `config.interval_seconds` until stopped or bounded.

    Returns the number of cruise iterations actually completed. On each pass it
    runs cruise, builds a summary, prints it, and pushes it to every sink. Sink
    failures (e.g. a down Slack webhook) are caught and logged so one bad sink
    never kills the loop. Between passes it sleeps the interval in short slices
    so a stop signal is honoured promptly.
    """
    stopper = _install_signal_handlers()
    cruise_fn = config.resolve_cruise()

    completed = 0
    while not stopper.requested:
        when = config.clock()
        try:
            diff = cruise_fn(config.db_path)
        except Exception as exc:  # noqa: BLE001 — a scan failure must not crash the daemon
            config.printer(f"[cruise #{completed + 1} @ {when}] ERROR: {exc}")
            diff = None

        completed += 1

        if diff is not None:
            should_emit = diff_has_changes(diff) or not config.quiet_when_unchanged
            if should_emit:
                summary = summarise_diff(diff, iteration=completed, when=when)
                config.printer(summary)
                _dispatch_sinks(config, summary)

        if config.iterations is not None and completed >= config.iterations:
            break
        if stopper.requested:
            break

        _interruptible_sleep(config.interval_seconds, config.sleeper, stopper)

    return completed


def _dispatch_sinks(config: WatchConfig, summary: str) -> None:
    """Send a summary to every configured sink, logging per-sink failures."""
    for sink in config.sinks:
        try:
            sink.send(summary)
        except Exception as exc:  # noqa: BLE001 — a flaky sink must not kill the loop
            config.printer(f"  ! notify sink {type(sink).__name__} failed: {exc}")


def _interruptible_sleep(
    seconds: float, sleeper: Callable[[float], None], stopper: _Stopper
) -> None:
    """Sleep `seconds` in <=1s slices, bailing early on a stop request.

    Slicing keeps SIGTERM responsive during a long (e.g. 4-hour) interval
    without busy-waiting. The injected `sleeper` is real `time.sleep` in
    production and a no-op spy in tests.
    """
    remaining = seconds
    while remaining > 0 and not stopper.requested:
        slice_len = min(1.0, remaining)
        sleeper(slice_len)
        remaining -= slice_len


def _install_signal_handlers() -> _Stopper:
    """Install SIGTERM/SIGINT handlers and return the shared stop flag.

    Best-effort: on platforms or contexts where a handler can't be installed
    (e.g. a non-main thread), the loop still terminates via its iteration bound.
    """
    stopper = _Stopper()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, stopper.request)
        except (ValueError, OSError):
            pass
    return stopper


def summary_as_json(diff: dict, *, iteration: int, when: str) -> str:
    """Render a cruise diff as a single JSON line (for machine-readable sinks).

    Kept alongside the human summary so a downstream consumer that prefers
    structured input can be wired up without re-deriving the envelope. Not used
    by the default CLI path but exercised by tests and available to callers.
    """
    return json.dumps(
        {"iteration": iteration, "when": when, "diff": diff},
        sort_keys=True,
    )
