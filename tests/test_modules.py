"""Tests for ossuary's probe and watch helper modules.

Covers tech-fingerprinting functions in probe.py and pure-logic helpers in
watch.py (interval parsing, sink parsing, diff summarisation). No live HTTP
calls or nmap shell-outs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ossuary.probe import (
    _extract_title,
    _fingerprint_headers,
    _fingerprint_html,
    extract_versioned_techs,
)
from ossuary.watch import (
    FileSink,
    SlackSink,
    WatchConfig,
    diff_has_changes,
    parse_interval,
    parse_notify,
    summarise_diff,
    summary_as_json,
)


# ---------------------------------------------------------------------------
# probe._fingerprint_headers
# ---------------------------------------------------------------------------


def test_fingerprint_headers_nginx():
    techs = _fingerprint_headers({"server": "nginx/1.24.0"})
    assert "nginx" in techs


def test_fingerprint_headers_apache():
    techs = _fingerprint_headers({"server": "Apache/2.4.49 (Ubuntu)"})
    assert "apache" in techs


def test_fingerprint_headers_iis():
    techs = _fingerprint_headers({"server": "Microsoft-IIS/10.0"})
    assert "iis" in techs


def test_fingerprint_headers_php_x_powered_by():
    techs = _fingerprint_headers({"x-powered-by": "PHP/8.1.2"})
    assert "php" in techs


def test_fingerprint_headers_aspnet_x_powered_by():
    techs = _fingerprint_headers({"x-powered-by": "ASP.NET"})
    assert "asp.net" in techs


def test_fingerprint_headers_drupal_cache_header():
    techs = _fingerprint_headers({"x-drupal-cache": "HIT"})
    assert "drupal" in techs


def test_fingerprint_headers_wordpress_header():
    techs = _fingerprint_headers({"x-generator": "WordPress 6.1"})
    assert "wordpress" in techs


def test_fingerprint_headers_no_signals_returns_empty():
    techs = _fingerprint_headers({"content-type": "text/html"})
    assert techs == []


def test_fingerprint_headers_no_duplicate_techs():
    # Both Server and X-Powered-By claim PHP — should deduplicate
    headers = {"x-powered-by": "PHP/8.1.2", "set-cookie": "PHPSESSID=abc"}
    techs = _fingerprint_headers(headers)
    assert techs.count("php") == 1


def test_fingerprint_headers_express_x_powered_by():
    techs = _fingerprint_headers({"x-powered-by": "Express"})
    assert "express" in techs


def test_fingerprint_headers_shopify():
    techs = _fingerprint_headers({"x-shopify-stage": "production"})
    assert "shopify" in techs


# ---------------------------------------------------------------------------
# probe._fingerprint_html
# ---------------------------------------------------------------------------


def test_fingerprint_html_detects_wordpress_wp_content():
    techs = _fingerprint_html('<link rel="stylesheet" href="/wp-content/themes/x.css">', [])
    assert "wordpress" in techs


def test_fingerprint_html_detects_drupal_settings():
    techs = _fingerprint_html('<script>drupal.settings = {}</script>', [])
    assert "drupal" in techs


def test_fingerprint_html_does_not_duplicate_existing_tech():
    techs = _fingerprint_html('<link href="/wp-content/x.css">', ["wordpress"])
    assert techs.count("wordpress") == 1


def test_fingerprint_html_joomla_via_generator():
    html = '<meta name="generator" content="Joomla! 4.0">'
    techs = _fingerprint_html(html, [])
    assert "joomla" in techs


# ---------------------------------------------------------------------------
# probe._extract_title
# ---------------------------------------------------------------------------


def test_extract_title_simple():
    assert _extract_title("<title>Hello World</title>") == "Hello World"


def test_extract_title_case_insensitive():
    assert _extract_title("<TITLE>Admin Panel</TITLE>") == "Admin Panel"


def test_extract_title_none_when_absent():
    assert _extract_title("<html><body>No title here</body></html>") is None


def test_extract_title_whitespace_stripped():
    assert _extract_title("<title>  Padded  </title>") == "Padded"


# ---------------------------------------------------------------------------
# probe.extract_versioned_techs
# ---------------------------------------------------------------------------


def test_extract_versioned_techs_nginx():
    pairs = extract_versioned_techs("nginx/1.24.0")
    assert ("nginx", "1.24.0") in pairs


def test_extract_versioned_techs_apache_maps_to_http_server():
    pairs = extract_versioned_techs("Apache/2.4.49 (Ubuntu)")
    assert ("http_server", "2.4.49") in pairs


def test_extract_versioned_techs_php():
    pairs = extract_versioned_techs("PHP/8.1.2")
    assert ("php", "8.1.2") in pairs


def test_extract_versioned_techs_no_version_returns_empty():
    assert extract_versioned_techs("nginx") == []


def test_extract_versioned_techs_unknown_product_ignored():
    # "Humperdink" is not in the banner map
    pairs = extract_versioned_techs("Humperdink/1.0")
    assert pairs == []


def test_extract_versioned_techs_multiple_banners():
    pairs = extract_versioned_techs("nginx/1.24.0", "PHP/8.1.2")
    products = [p[0] for p in pairs]
    assert "nginx" in products
    assert "php" in products


def test_extract_versioned_techs_deduplicates():
    # Same banner passed twice — only one entry
    pairs = extract_versioned_techs("nginx/1.24.0", "nginx/1.24.0")
    assert pairs.count(("nginx", "1.24.0")) == 1


def test_extract_versioned_techs_none_banner_ignored():
    pairs = extract_versioned_techs(None, "nginx/1.24.0")
    assert ("nginx", "1.24.0") in pairs


# ---------------------------------------------------------------------------
# watch.parse_interval
# ---------------------------------------------------------------------------


def test_parse_interval_bare_integer():
    assert parse_interval("300") == 300


def test_parse_interval_seconds_suffix():
    assert parse_interval("90s") == 90


def test_parse_interval_minutes_suffix():
    assert parse_interval("30m") == 1800


def test_parse_interval_hours_suffix():
    assert parse_interval("4h") == 14400


def test_parse_interval_days_suffix():
    assert parse_interval("1d") == 86400


def test_parse_interval_uppercase_suffix():
    # the function lowercases internally
    assert parse_interval("2H") == 7200


def test_parse_interval_invalid_string_raises():
    with pytest.raises(ValueError, match="invalid interval"):
        parse_interval("abc")


def test_parse_interval_zero_raises():
    with pytest.raises(ValueError, match="positive"):
        parse_interval("0")


def test_parse_interval_negative_raises():
    with pytest.raises(ValueError, match="positive"):
        parse_interval("-5m")


def test_parse_interval_empty_raises():
    with pytest.raises(ValueError):
        parse_interval("")


# ---------------------------------------------------------------------------
# watch.parse_notify
# ---------------------------------------------------------------------------


def test_parse_notify_file_returns_file_sink(tmp_path):
    sink = parse_notify(f"file:{tmp_path}/cruise.log")
    assert isinstance(sink, FileSink)


def test_parse_notify_slack_returns_slack_sink():
    sink = parse_notify("slack:https://hooks.slack.com/services/X/Y/Z")
    assert isinstance(sink, SlackSink)
    assert "https://hooks.slack.com" in sink.webhook


def test_parse_notify_unknown_kind_raises():
    with pytest.raises(ValueError, match="unknown --notify kind"):
        parse_notify("smtp:mail@example.com")


def test_parse_notify_no_colon_raises():
    with pytest.raises(ValueError, match="expected file"):
        parse_notify("nocolon")


def test_parse_notify_empty_target_raises():
    with pytest.raises(ValueError, match="empty target"):
        parse_notify("file:")


# ---------------------------------------------------------------------------
# watch.FileSink
# ---------------------------------------------------------------------------


def test_file_sink_appends_to_file(tmp_path):
    p = tmp_path / "logs" / "out.log"
    sink = FileSink(p)
    sink.send("first")
    sink.send("second")
    content = p.read_text()
    assert "first" in content
    assert "second" in content


def test_file_sink_creates_parent_dirs(tmp_path):
    p = tmp_path / "nested" / "dir" / "cruise.log"
    sink = FileSink(p)
    sink.send("hello")
    assert p.exists()


# ---------------------------------------------------------------------------
# watch.summarise_diff / diff_has_changes / summary_as_json
# ---------------------------------------------------------------------------


def test_summarise_diff_no_changes_says_no_changes():
    diff = {"added": [], "removed": [], "changed": [], "tag_changes": []}
    summary = summarise_diff(diff, iteration=1, when="2026-05-01T12:00:00")
    assert "(no changes)" in summary
    assert "cruise #1" in summary


def test_summarise_diff_reports_added_service():
    diff = {
        "added": [{"service": "10.0.0.5:tcp/80", "detail": {"product": "nginx", "version": "1.25.0"}}],
        "removed": [],
        "changed": [],
        "tag_changes": [],
    }
    summary = summarise_diff(diff, iteration=2, when="2026-05-01T16:00:00")
    assert "+ 10.0.0.5:tcp/80" in summary
    assert "nginx 1.25.0" in summary


def test_summarise_diff_reports_removed_service():
    diff = {
        "added": [],
        "removed": [{"service": "10.0.0.5:tcp/22", "detail": {"product": "OpenSSH", "version": "8.9p1"}}],
        "changed": [],
        "tag_changes": [],
    }
    summary = summarise_diff(diff, iteration=3, when="2026-05-01T20:00:00")
    assert "- 10.0.0.5:tcp/22" in summary


def test_summarise_diff_reports_tag_changes():
    diff = {
        "added": [],
        "removed": [],
        "changed": [],
        "tag_changes": [{"asset": "10.0.0.5", "added": ["vip"], "removed": []}],
    }
    summary = summarise_diff(diff, iteration=1, when="2026-05-01T12:00:00")
    assert "10.0.0.5" in summary
    assert "+vip" in summary


def test_diff_has_changes_false_on_empty():
    diff = {"added": [], "removed": [], "changed": [], "tag_changes": []}
    assert not diff_has_changes(diff)


def test_diff_has_changes_true_on_added():
    diff = {"added": [{"service": "x"}], "removed": [], "changed": [], "tag_changes": []}
    assert diff_has_changes(diff)


def test_diff_has_changes_true_on_tag_change():
    diff = {"added": [], "removed": [], "changed": [], "tag_changes": [{"asset": "x"}]}
    assert diff_has_changes(diff)


def test_summary_as_json_is_valid_json():
    import json
    diff = {"added": [], "removed": [], "changed": []}
    text = summary_as_json(diff, iteration=1, when="2026-05-01T12:00:00")
    doc = json.loads(text)
    assert doc["iteration"] == 1
    assert "diff" in doc
