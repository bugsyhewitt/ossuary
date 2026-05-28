"""Tests for the scheduled cruise daemon (`ossuary watch`, POST_V01 Rank 5).

The whole daemon is exercised offline with zero wall-clock waiting: the cruise
call, the sleeper, and the clock are injectable seams (see watch.WatchConfig),
so a multi-pass loop runs instantly and deterministically. No scheduler, no
network — Slack sinks are driven through an injected fake HTTP client.
"""

from __future__ import annotations

import json

import httpx
import pytest

from ossuary import cli, db, watch


# --------------------------------------------------------------------------
# parse_interval
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("4h", 4 * 3600),
        ("30m", 30 * 60),
        ("90s", 90),
        ("1d", 86400),
        ("300", 300),  # bare integer == seconds
        (" 2H ", 2 * 3600),  # whitespace + uppercase tolerated
    ],
)
def test_parse_interval_valid(spec, expected):
    assert watch.parse_interval(spec) == expected


@pytest.mark.parametrize("spec", ["", "  ", "abc", "4x", "-5m", "0", "0h", "1.5h"])
def test_parse_interval_invalid(spec):
    with pytest.raises(ValueError):
        watch.parse_interval(spec)


# --------------------------------------------------------------------------
# parse_notify
# --------------------------------------------------------------------------


def test_parse_notify_file(tmp_path):
    sink = watch.parse_notify(f"file:{tmp_path / 'out.log'}")
    assert isinstance(sink, watch.FileSink)
    assert sink.path == tmp_path / "out.log"


def test_parse_notify_slack_preserves_https_url():
    url = "https://hooks.slack.com/services/T000/B000/XXX"
    sink = watch.parse_notify(f"slack:{url}")
    assert isinstance(sink, watch.SlackSink)
    assert sink.webhook == url


@pytest.mark.parametrize("spec", ["nope", "file:", "slack:", "carrier-pigeon:foo"])
def test_parse_notify_invalid(spec):
    with pytest.raises(ValueError):
        watch.parse_notify(spec)


# --------------------------------------------------------------------------
# summarise_diff
# --------------------------------------------------------------------------


def _sample_diff():
    return {
        "added": [
            {"service": "10.0.0.5:tcp/443", "detail": {"product": "nginx", "version": "1.25.0"}}
        ],
        "removed": [
            {"service": "10.0.0.5:tcp/22", "detail": {"product": "OpenSSH", "version": "8.9p1"}}
        ],
        "changed": [
            {
                "service": "10.0.0.5:tcp/80",
                "from": {"product": "nginx", "version": "1.18.0"},
                "to": {"product": "nginx", "version": "1.25.0"},
            }
        ],
        "tag_changes": [
            {"asset": "10.0.0.5", "added": ["vip"], "removed": ["noise"]}
        ],
    }


def test_summarise_diff_lists_every_change():
    summary = watch.summarise_diff(_sample_diff(), iteration=3, when="2026-05-28T00:00:00")
    assert "cruise #3" in summary
    assert "1 added, 1 removed, 1 changed, 1 tag change(s)" in summary
    assert "+ 10.0.0.5:tcp/443" in summary
    assert "- 10.0.0.5:tcp/22" in summary
    assert "~ 10.0.0.5:tcp/80  nginx 1.18.0 -> nginx 1.25.0" in summary
    assert "# 10.0.0.5  tags +vip -noise" in summary


def test_summarise_diff_reports_no_changes_explicitly():
    empty = {"added": [], "removed": [], "changed": [], "tag_changes": []}
    summary = watch.summarise_diff(empty, iteration=1, when="t")
    assert "(no changes)" in summary


def test_diff_has_changes():
    assert watch.diff_has_changes(_sample_diff()) is True
    assert watch.diff_has_changes({"added": [], "removed": [], "changed": [], "tag_changes": []}) is False


# --------------------------------------------------------------------------
# the watch loop
# --------------------------------------------------------------------------


def _no_change_diff():
    return {"added": [], "removed": [], "changed": [], "tag_changes": []}


def test_watch_runs_bounded_iterations_without_real_sleep():
    calls = {"cruise": 0, "sleeps": []}

    def fake_cruise(_db):
        calls["cruise"] += 1
        return _sample_diff()

    config = watch.WatchConfig(
        db_path="x.db",
        interval_seconds=4 * 3600,
        iterations=3,
        cruise_fn=fake_cruise,
        sleeper=lambda s: calls["sleeps"].append(s),
        clock=lambda: "T",
        printer=lambda _m: None,
    )
    completed = watch.watch(config)

    assert completed == 3
    assert calls["cruise"] == 3
    # Sleeps happen between passes, not after the last one: 2 gaps, sliced to <=1s.
    assert calls["sleeps"], "expected the loop to sleep between passes"
    assert all(s <= 1.0 for s in calls["sleeps"])


def test_watch_dispatches_to_sinks(tmp_path):
    out_file = tmp_path / "diffs.log"
    sent = []

    class _SpySink:
        def send(self, summary):
            sent.append(summary)

    config = watch.WatchConfig(
        db_path="x.db",
        interval_seconds=1,
        iterations=2,
        sinks=[watch.FileSink(out_file), _SpySink()],
        cruise_fn=lambda _db: _sample_diff(),
        sleeper=lambda _s: None,
        clock=lambda: "T",
        printer=lambda _m: None,
    )
    watch.watch(config)

    # File sink wrote two newline-delimited blocks.
    contents = out_file.read_text()
    assert contents.count("cruise #") == 2
    # Spy sink also received both.
    assert len(sent) == 2


def test_watch_quiet_when_unchanged_suppresses_empty_passes():
    emitted = []

    config = watch.WatchConfig(
        db_path="x.db",
        interval_seconds=1,
        iterations=3,
        quiet_when_unchanged=True,
        cruise_fn=lambda _db: _no_change_diff(),
        sleeper=lambda _s: None,
        clock=lambda: "T",
        printer=lambda m: emitted.append(m),
    )
    completed = watch.watch(config)

    assert completed == 3
    # Nothing changed on any pass, so quiet mode suppresses all summaries.
    assert emitted == []


def test_watch_sink_failure_does_not_kill_loop():
    messages = []

    class _BrokenSink:
        def send(self, _summary):
            raise RuntimeError("webhook down")

    config = watch.WatchConfig(
        db_path="x.db",
        interval_seconds=1,
        iterations=2,
        sinks=[_BrokenSink()],
        cruise_fn=lambda _db: _sample_diff(),
        sleeper=lambda _s: None,
        clock=lambda: "T",
        printer=lambda m: messages.append(m),
    )
    completed = watch.watch(config)

    assert completed == 2  # loop survived both broken-sink passes
    assert any("notify sink" in m and "failed" in m for m in messages)


def test_watch_cruise_failure_does_not_kill_loop():
    messages = []

    def flaky_cruise(_db):
        raise RuntimeError("nmap exploded")

    config = watch.WatchConfig(
        db_path="x.db",
        interval_seconds=1,
        iterations=2,
        cruise_fn=flaky_cruise,
        sleeper=lambda _s: None,
        clock=lambda: "T",
        printer=lambda m: messages.append(m),
    )
    completed = watch.watch(config)

    assert completed == 2
    assert any("ERROR" in m for m in messages)


def test_watch_honours_stop_signal_mid_run(monkeypatch):
    # Simulate SIGTERM arriving after the first pass by flipping the stopper.
    stoppers = []
    real_install = watch._install_signal_handlers

    def capture_install():
        s = real_install()
        stoppers.append(s)
        return s

    monkeypatch.setattr(watch, "_install_signal_handlers", capture_install)

    def cruise_then_stop(_db):
        stoppers[0].requested = True
        return _sample_diff()

    config = watch.WatchConfig(
        db_path="x.db",
        interval_seconds=1,
        iterations=None,  # would run forever without the stop signal
        cruise_fn=cruise_then_stop,
        sleeper=lambda _s: None,
        clock=lambda: "T",
        printer=lambda _m: None,
    )
    completed = watch.watch(config)
    assert completed == 1  # stopped after the first pass despite no iteration bound


# --------------------------------------------------------------------------
# SlackSink with an injected fake HTTP client
# --------------------------------------------------------------------------


def test_slack_sink_posts_text_payload():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["json"] = json.loads(request.content)
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    url = "https://hooks.slack.com/services/T/B/X"
    sink = watch.SlackSink(
        url,
        _client_factory=lambda: httpx.Client(transport=transport),
    )
    sink.send("hello cruise")

    assert captured["url"] == url
    assert captured["json"] == {"text": "hello cruise"}


def test_slack_sink_raises_on_http_error():
    transport = httpx.MockTransport(lambda req: httpx.Response(500))
    sink = watch.SlackSink(
        "https://hooks.slack.com/services/T/B/X",
        _client_factory=lambda: httpx.Client(transport=transport),
    )
    with pytest.raises(httpx.HTTPStatusError):
        sink.send("boom")


# --------------------------------------------------------------------------
# CLI integration
# --------------------------------------------------------------------------


def test_watch_help_listed(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "watch" in capsys.readouterr().out


def test_cli_watch_uninitialised_db_errors(tmp_path, capsys):
    rc = cli.main(["watch", "--db", str(tmp_path / "missing.db"), "--once"])
    assert rc == 1
    assert "not initialised" in capsys.readouterr().err


def test_cli_watch_once_runs_one_pass(tmp_path, monkeypatch, capsys):
    db_file = str(tmp_path / "engagement.db")
    db.init_db(db_file).close()

    # The CLI builds WatchConfig with the default cruise_fn, which resolves to
    # cruise_mod.cruise lazily — so patching it here takes effect.
    monkeypatch.setattr(watch.cruise_mod, "cruise", lambda _db: _no_change_diff())
    monkeypatch.setattr(watch.time, "sleep", lambda _s: None)

    rc = cli.main(["watch", "--db", db_file, "--interval", "1s", "--once"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "watching" in out
    assert "watch stopped after 1 cruise pass(es)" in out


def test_cli_watch_notify_file_writes_summaries(tmp_path, monkeypatch, capsys):
    db_file = str(tmp_path / "engagement.db")
    db.init_db(db_file).close()
    out_file = tmp_path / "diffs.log"

    monkeypatch.setattr(watch.cruise_mod, "cruise", lambda _db: _sample_diff())
    monkeypatch.setattr(watch.time, "sleep", lambda _s: None)

    rc = cli.main(
        [
            "watch",
            "--db",
            db_file,
            "--interval",
            "1s",
            "--iterations",
            "2",
            "--notify",
            f"file:{out_file}",
        ]
    )
    assert rc == 0
    assert out_file.read_text().count("cruise #") == 2
