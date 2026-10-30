"""Offline tests. No internet needed: feeds, KEV and NVD are served locally."""

import functools
import http.server
import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import briefing as b  # noqa: E402

# 08:00 Mountain on Oct 30 2026 (MDT, UTC-6) is 14:00 UTC.
T0 = datetime(2026, 10, 30, 14, 0, tzinfo=timezone.utc)


def rss(items):
    body = "".join(
        f"<item><title>{t}</title><link>{l}</link><description>{d}</description>"
        f"<pubDate>{p:%a, %d %b %Y %H:%M:%S +0000}</pubDate></item>"
        for t, l, d, p in items
    )
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>{body}</channel></rss>'


def atom(entries):
    body = "".join(
        f"<entry><title>{t}</title><link href='{l}'/><id>{l}</id>"
        f"<updated>{p:%Y-%m-%dT%H:%M:%SZ}</updated></entry>"
        for t, l, p in entries
    )
    return (
        '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">'
        f"<title>x</title><id>x</id><updated>2026-10-30T00:00:00Z</updated>{body}</feed>"
    )


@pytest.fixture()
def env(tmp_path, monkeypatch):
    web = tmp_path / "web"
    web.mkdir()
    recent = T0 - timedelta(hours=3)
    (web / "ai.xml").write_text(rss([
        ("Threat actors use AI-enabled malware against power grid utilities",
         "http://example.test/a1", "state-sponsored group abuses an LLM", recent),
        ("New phone released", "http://example.test/a2", "shiny", recent),
    ]))
    (web / "empty.xml").write_text(atom([]))
    (web / "cairn.xml").write_text(atom([("Add family report", "http://example.test/c1", recent)]))
    (web / "notafeed.xml").write_text("<html><body>Access denied</body></html>")
    (web / "kev.json").write_text(json.dumps({"vulnerabilities": [{
        "cveID": "CVE-2026-1111", "vendorProject": "Siemens", "product": "SCADA",
        "dateAdded": "2026-10-30", "dueDate": "2026-11-20",
        "knownRansomwareCampaignUse": "Known", "shortDescription": "bad"}]}))
    (web / "nvd.json").write_text(json.dumps({
        "vulnerabilities": [{"cve": {"id": "CVE-2026-2222", "descriptions": [
            {"lang": "en", "value": "Flaw in substation controller firmware"}]}}],
        "resultsPerPage": 1, "totalResults": 1}))

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(web))
    handler.log_message = lambda *a, **k: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"

    feeds = [
        {"name": "AI Feed", "url": f"{base}/ai.xml", "boost": 0},
        {"name": "Empty Feed", "url": f"{base}/empty.xml"},
        {"name": "Blocked Feed", "url": f"{base}/notafeed.xml"},
        {"name": "Missing Feed", "url": f"{base}/missing.xml"},
        {"name": "CAIRN", "url": f"{base}/cairn.xml", "mode": "all", "flag": "CAIRN"},
        {"name": "Disabled", "url": f"{base}/ai.xml", "enabled": False},
    ]
    feeds_file = tmp_path / "feeds.json"
    feeds_file.write_text(json.dumps(feeds))

    state_dir = tmp_path / "state"
    monkeypatch.setattr(b, "FEEDS_PATH", feeds_file)
    monkeypatch.setattr(b, "KEV_URL", f"{base}/kev.json")
    monkeypatch.setattr(b, "NVD_URL", f"{base}/nvd.json")
    monkeypatch.setattr(b, "STATE_DIR", state_dir)
    monkeypatch.setattr(b, "STATE_FILE", state_dir / "state.json")
    monkeypatch.setattr(b, "CHANGED_MARKER", state_dir / "CHANGED")
    monkeypatch.setattr(b, "BACKOFF", 0)
    monkeypatch.setattr(b, "NVD_DELAY_NO_KEY", 0)
    sent = []
    monkeypatch.setattr(b, "deliver_to_discord", lambda text: sent.append(text))
    yield {"sent": sent, "set_now": lambda dt: monkeypatch.setattr(b, "utcnow", lambda: dt)}
    server.shutdown()


# ---- scheduling -----------------------------------------------------------


def mt(h, m):
    return datetime(2026, 10, 30, h, m, tzinfo=b.MT)


def test_due_modes():
    st = b._blank_state()
    assert b.due_modes(mt(7, 59), st) == []
    assert b.due_modes(mt(8, 30), st) == ["morning"]
    assert b.due_modes(mt(9, 10), st) == ["morning", "update"]
    st["posted"]["2026-10-30"] = {"morning": "x"}
    assert b.due_modes(mt(9, 10), st) == ["update"]
    st["posted"]["2026-10-30"]["update"] = "x"
    assert b.due_modes(mt(10, 40), st) == []


def test_dst_math_is_mountain_time():
    assert datetime(2026, 10, 30, 14, 0, tzinfo=timezone.utc).astimezone(b.MT).hour == 8
    assert datetime(2026, 11, 2, 15, 0, tzinfo=timezone.utc).astimezone(b.MT).hour == 8


# ---- scoring --------------------------------------------------------------


def test_scoring_uses_word_boundaries():
    assert b.score_text("A paid plan for the maid")[0] == 0
    score, flags = b.score_text("Nation-state actors use an LLM against the power grid")
    assert {"AI-THREAT", "SECTOR"} <= flags and score >= b.MIN_SCORE
    assert "AI-THREAT" not in b.score_text("New LLM released today")[1]
    assert "CAIRN" in b.score_text("Talos introduces CAIRN")[1]


def test_chunking_respects_limit():
    text = "\n".join(["x" * 5000, "y" * 100] * 30)
    assert all(len(c) <= 1900 for c in b.chunk_text(text))


# ---- feeds ----------------------------------------------------------------


def test_one_bad_feed_does_not_stop_the_rest(env):
    now = T0
    items, health = b.collect_news(b.load_feeds(), now - timedelta(hours=36), now)
    by = {h["name"]: h for h in health}
    assert "Disabled" not in by
    assert by["AI Feed"]["ok"] and by["Empty Feed"]["ok"] and by["CAIRN"]["ok"]
    assert not by["Blocked Feed"]["ok"] and "valid feed" in by["Blocked Feed"]["error"]
    assert not by["Missing Feed"]["ok"] and "404" in by["Missing Feed"]["error"]
    titles = [i.title for i in items]
    assert any("AI-enabled malware" in t for t in titles)
    assert not any("phone" in t for t in titles)
    assert any("CAIRN" in i.flags for i in items)


# ---- end to end -----------------------------------------------------------


def test_morning_post_then_nothing_due_then_update(env):
    env["set_now"](T0 + timedelta(minutes=2))          # 08:02 MT
    assert b.main(["--mode", "auto"]) == 0
    assert len(env["sent"]) == 1
    text = env["sent"][0]
    assert "CVE-2026-1111" in text and "AI-THREAT" in text and "CAIRN" in text
    assert "CVE-2026-2222" in text
    assert "Failed: Blocked Feed" in text and "Missing Feed" in text
    assert "Delayed run" not in text

    assert b.main(["--mode", "auto"]) == 0             # same minute: nothing due
    assert len(env["sent"]) == 1

    env["set_now"](T0 + timedelta(hours=1, minutes=3))  # 09:03 MT
    assert b.main(["--mode", "auto"]) == 0
    assert len(env["sent"]) == 2
    update = env["sent"][1]
    assert "No new items" in update and "CVE-2026-1111" not in update  # deduped


def test_late_run_posts_morning_once_and_supersedes_update(env):
    env["set_now"](T0 + timedelta(hours=5, minutes=20))  # 13:20 MT
    assert b.main(["--mode", "auto"]) == 0
    assert len(env["sent"]) == 1 and "Delayed run" in env["sent"][0]
    assert "5h 20m late" in env["sent"][0]
    state = json.loads(b.STATE_FILE.read_text())
    assert state["posted"]["2026-10-30"]["update"] == "superseded"
    assert b.main(["--mode", "auto"]) == 0
    assert len(env["sent"]) == 1


def test_manual_test_run_records_nothing(env):
    env["set_now"](T0)
    assert b.main(["--mode", "morning"]) == 0
    assert len(env["sent"]) == 1
    assert not b.STATE_FILE.exists() and not b.CHANGED_MARKER.exists()


def test_dry_run_does_not_post_or_record(env, capsys):
    env["set_now"](T0 + timedelta(minutes=2))
    assert b.main(["--mode", "auto", "--dry-run"]) == 0
    assert env["sent"] == [] and not b.STATE_FILE.exists()
    assert "CVE-2026-1111" in capsys.readouterr().out


def test_all_sources_down_exits_nonzero(env, monkeypatch):
    monkeypatch.setattr(b, "KEV_URL", "http://127.0.0.1:9/none")
    monkeypatch.setattr(b, "NVD_URL", "http://127.0.0.1:9/none")
    monkeypatch.setattr(b, "load_feeds", lambda: [{"name": "x", "url": "http://127.0.0.1:9/x"}])
    env["set_now"](T0)
    assert b.main(["--mode", "morning"]) == 1
    assert env["sent"] == []


def test_state_prunes_old_entries():
    st = b._blank_state()
    st["seen"]["kev"] = {"old": "2026-01-01", "new": "2026-10-29"}
    b.prune_state(st, T0)
    assert list(st["seen"]["kev"]) == ["new"]
