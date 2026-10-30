#!/usr/bin/env python3
"""Power / critical-infrastructure cyber brief, delivered to Discord.

Modes
  auto      Post whatever is due right now (8:00 morning, 9:00 update, Mountain
            Time) unless it was already posted today. Safe to run many times.
  morning   Test run. Nothing is recorded.
  update    Test run. Nothing is recorded.

Flags
  --dry-run       Build the brief and print it, do not post.
  --check-feeds   Test every feed in feeds.json and report health, do not post.
"""

from __future__ import annotations

import argparse
import calendar
import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import feedparser
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

MT = ZoneInfo("America/Denver")
NVD_URL = os.getenv("NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
KEV_URL = os.getenv(
    "KEV_URL",
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json",
)
FEEDS_PATH = Path(os.getenv("FEEDS_FILE", Path(__file__).with_name("feeds.json")))
STATE_DIR = Path(os.getenv("STATE_DIR", "state"))
STATE_FILE = STATE_DIR / "state.json"
CHANGED_MARKER = STATE_DIR / "CHANGED"

SLOTS = {"morning": (8, 0), "update": (9, 0)}  # Mountain Time
LATE_AFTER = timedelta(minutes=20)
MAX_LOOKBACK = timedelta(hours=36)
OVERLAP = timedelta(minutes=30)
FIRST_UPDATE_LOOKBACK = timedelta(hours=2)
SEEN_KEEP_DAYS = 14
MIN_SCORE = 3
CAPS = {"kev": 25, "ai": 12, "nvd": 20, "news": 15}
BACKOFF = 1.0
NVD_DELAY_NO_KEY = 6.0
NVD_DELAY_WITH_KEY = 0.7
USER_AGENT = (
    "Daily-Cyber-Feed/2.0 (+https://github.com/forge-lab-dev/Daily-Cyber-Feed)"
)

SESSION = requests.Session()
SESSION.headers["User-Agent"] = USER_AGENT
SESSION.headers["Accept"] = (
    "application/atom+xml, application/rss+xml, application/xml, "
    "application/json, text/xml;q=0.9, */*;q=0.5"
)

# --------------------------------------------------------------------------
# Term lists and scoring
# --------------------------------------------------------------------------


def _compile(terms):
    parts = [
        r"(?<![a-z0-9])" + re.escape(t.lower()) + r"(?![a-z0-9])"
        for t in terms
        if t and t.strip()
    ]
    return re.compile("|".join(parts)) if parts else None


def _hits(rx, text):
    return sorted(set(rx.findall(text))) if rx else []


PRIORITY_TERMS = [
    x.strip().lower()
    for x in os.getenv("ASSET_KEYWORDS", "").split(",")
    if x.strip()
]

SECTOR_TERMS = [
    "electric utility", "power grid", "substation", "electricity",
    "industrial control", "operational technology", "scada", "ics",
    "energy sector", "power plant", "transmission grid", "transmission line",
    "distribution utility", "data center", "critical infrastructure",
    "water utility", "oil and gas",
]

AI_TERMS = [
    "ai-enabled", "ai-powered", "ai-assisted", "ai-integrated", "ai-driven",
    "ai-generated", "ai agent", "ai agents", "agentic", "llm", "llms",
    "large language model", "generative ai", "genai", "chatgpt", "gemini",
    "claude", "copilot", "openai", "deepseek", "prompt injection", "jailbreak",
    "model context protocol", "deepfake", "ai model", "ai tool", "ai tools",
    "artificial intelligence",
]

ACTOR_TERMS = [
    "threat actor", "threat actors", "apt", "state-sponsored", "state sponsored",
    "nation-state", "nation state", "china-nexus", "russia-nexus", "iran-nexus",
    "north korea", "dprk", "volt typhoon", "salt typhoon", "sandworm", "apt28",
    "apt29", "apt41", "lazarus", "ransomware", "cybercriminal", "cybercriminals",
    "hacktivist", "hacktivists", "espionage", "malware", "intrusion",
    "malicious use", "malicious uses", "misuse", "influence operation",
    "adversary", "adversaries", "attackers",
]

CAIRN_TERMS = [
    "cairn", "cognitive artifact", "ai-integrated malware", "closedquorum",
    "closed quorum", "lamehug",
]

GENERIC_TERMS = [
    "zero-day", "zero day", "exploited", "cyberattack", "cyber attack",
    "vulnerability", "breach",
]

PRIORITY_RX = _compile(PRIORITY_TERMS)
SECTOR_RX = _compile(SECTOR_TERMS)
AI_RX = _compile(AI_TERMS)
ACTOR_RX = _compile(ACTOR_TERMS)
CAIRN_RX = _compile(CAIRN_TERMS)
GENERIC_RX = _compile(GENERIC_TERMS)


def score_text(text, boost=0):
    """Return (score, flags). Short terms use word boundaries, so 'ai' or
    'ics' do not match inside other words."""
    t = text.lower()
    score = boost
    flags = set()
    if _hits(CAIRN_RX, t):
        score += 10
        flags.add("CAIRN")
    if _hits(PRIORITY_RX, t):
        score += 5
        flags.add("PRIORITY")
    if _hits(SECTOR_RX, t):
        score += 3
        flags.add("SECTOR")
    if _hits(AI_RX, t) and _hits(ACTOR_RX, t):
        score += 4
        flags.add("AI-THREAT")
    if _hits(GENERIC_RX, t):
        score += 1
    return score, flags


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


@dataclass
class NewsItem:
    source: str
    title: str
    link: str
    published: datetime
    score: int
    flags: set = field(default_factory=set)


def utcnow():
    return datetime.now(timezone.utc)


def clean(text, limit=180):
    """Single-line, Discord-safe text: no pipes (our separator), no backticks,
    no live @mentions."""
    text = html.unescape(re.sub(r"\s+", " ", text or "")).strip()
    text = text.replace("`", "'").replace("|", "/").replace("@", "@\u200b")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def strip_tags(text):
    return re.sub(r"<[^>]+>", " ", html.unescape(text or ""))[:1500]


def norm_link(url):
    return re.sub(r"[?#].*$", "", (url or "").strip().lower()).rstrip("/")


def norm_title(title):
    return re.sub(r"[^a-z0-9]+", "", (title or "").lower())[:70]


def short_error(err):
    if isinstance(err, requests.HTTPError) and err.response is not None:
        return f"HTTP {err.response.status_code}"
    return f"{type(err).__name__}: {err}"[:90]


def fmt_delta(delta):
    minutes = int(delta.total_seconds() // 60)
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins:02d}m" if hours else f"{mins}m"


def get_json(url, params=None, headers=None, retries=3):
    last = None
    for attempt in range(retries):
        try:
            response = SESSION.get(
                url, params=params, headers=headers, timeout=(5, 40)
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as error:
            last = error
            time.sleep(BACKOFF * 2 ** attempt)
    raise RuntimeError(f"Request failed: {url} ({short_error(last)})") from last


# --------------------------------------------------------------------------
# State (stored on the brief-state branch by the workflow)
# --------------------------------------------------------------------------


def _blank_state():
    return {"posted": {}, "seen": {"kev": {}, "nvd": {}, "news": {}}, "last_post_utc": None}


def load_state():
    state = _blank_state()
    try:
        loaded = json.loads(STATE_FILE.read_text())
    except (FileNotFoundError, ValueError, OSError):
        return state
    if isinstance(loaded, dict):
        state["posted"] = loaded.get("posted", {}) or {}
        seen = loaded.get("seen", {}) or {}
        for kind in ("kev", "nvd", "news"):
            state["seen"][kind] = seen.get(kind, {}) or {}
        state["last_post_utc"] = loaded.get("last_post_utc")
    return state


def prune_state(state, now):
    cutoff = (now - timedelta(days=SEEN_KEEP_DAYS)).date().isoformat()
    for kind in state["seen"]:
        state["seen"][kind] = {k: v for k, v in state["seen"][kind].items() if v >= cutoff}
    state["posted"] = {d: v for d, v in state["posted"].items() if d >= cutoff}


def save_state(state, now):
    prune_state(state, now)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1, sort_keys=True))
    CHANGED_MARKER.write_text("1")


def parse_utc(value):
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Scheduling logic
# --------------------------------------------------------------------------


def slot_time(now_mt, mode):
    hour, minute = SLOTS[mode]
    return now_mt.replace(hour=hour, minute=minute, second=0, microsecond=0)


def due_modes(now_mt, state):
    """Slots whose time has passed today (Mountain) and are not yet posted."""
    posted_today = state["posted"].get(now_mt.date().isoformat(), {})
    return [
        mode for mode in SLOTS
        if now_mt >= slot_time(now_mt, mode) and mode not in posted_today
    ]


def window_start(mode, now, state, use_state):
    """Brief covers the time since the last successful post (small overlap)."""
    last = parse_utc(state.get("last_post_utc")) if use_state else None
    if last and now - last < MAX_LOOKBACK:
        return last - OVERLAP
    return now - (MAX_LOOKBACK if mode == "morning" else FIRST_UPDATE_LOOKBACK)


# --------------------------------------------------------------------------
# Data sources
# --------------------------------------------------------------------------


def nvd_cves(start, now):
    key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    delay = NVD_DELAY_WITH_KEY if key else NVD_DELAY_NO_KEY
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "startIndex": 0,
    }
    results = []
    while True:
        data = get_json(NVD_URL, params=params, headers=headers)
        batch = data.get("vulnerabilities", [])
        results.extend(item["cve"] for item in batch)
        params["startIndex"] += data.get("resultsPerPage") or len(batch)
        if not batch or params["startIndex"] >= data.get("totalResults", 0):
            break
        time.sleep(delay)
    return results


def fetch_kev(start):
    data = get_json(KEV_URL)
    cutoff = start.date()
    found = []
    for item in data.get("vulnerabilities", []):
        try:
            added = datetime.strptime(item["dateAdded"], "%Y-%m-%d").date()
        except (KeyError, ValueError):
            continue
        if added >= cutoff:
            found.append(item)
    return found


def load_feeds():
    try:
        return json.loads(FEEDS_PATH.read_text())
    except FileNotFoundError:
        raise SystemExit(f"feeds.json not found at {FEEDS_PATH}. Commit it next to briefing.py.")


def fetch_feed(feed):
    """Fetch with a real timeout, then parse. Raises on anything that is not a
    valid feed (HTML error pages, blocked requests, bad URLs)."""
    response = SESSION.get(feed["url"], timeout=(5, 20))
    response.raise_for_status()
    parsed = feedparser.parse(response.content)
    if not parsed.version:
        raise ValueError("response is not a valid feed")
    return parsed.entries


def entry_time(entry):
    stamp = entry.get("published_parsed") or entry.get("updated_parsed")
    if not stamp:
        return None
    return datetime.fromtimestamp(calendar.timegm(stamp), timezone.utc)


def collect_news(feeds, start, now):
    """Fetch all enabled feeds. One broken feed never stops the others."""
    active = [f for f in feeds if f.get("enabled", True)]

    def work(feed):
        try:
            return feed, fetch_feed(feed), None
        except Exception as error:  # noqa: BLE001 - isolate every feed failure
            return feed, None, error

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(work, active))

    items, health = [], []
    for feed, entries, error in results:
        name = feed["name"]
        if error is not None:
            health.append({"name": name, "ok": False, "error": short_error(error)})
            continue
        kept = 0
        dated = [(entry_time(e), e) for e in entries]
        dated = [(t, e) for t, e in dated if t]
        dated.sort(key=lambda pair: pair[0], reverse=True)
        for published, entry in dated:
            if published < start:
                break
            title = entry.get("title", "")
            link = entry.get("link", "")
            if not title or not link:
                continue
            text = f"{title} {strip_tags(entry.get('summary', ''))}"
            score, flags = score_text(text, feed.get("boost", 0))
            if feed.get("flag"):
                flags.add(feed["flag"])
                score += 10
            if feed.get("mode") != "all" and score < MIN_SCORE:
                continue
            items.append(NewsItem(name, title, link, published, score, flags))
            kept += 1
            if kept >= feed.get("max_items", 50):
                break
        health.append({"name": name, "ok": True, "items": kept})

    return dedupe_news(items), health


def dedupe_news(items):
    """Same story from several feeds: keep the highest-scoring copy."""
    taken, kept = set(), []
    for item in sorted(items, key=lambda i: i.score, reverse=True):
        keys = {norm_link(item.link), norm_title(item.title)}
        if keys & taken:
            continue
        taken |= keys
        kept.append(item)
    return kept


# --------------------------------------------------------------------------
# Brief assembly
# --------------------------------------------------------------------------


def priority_hits(text):
    return _hits(PRIORITY_RX, text.lower())


def _more(lines, total, shown):
    if total > shown:
        lines.append(f"…and {total - shown} more not shown.")


def build_brief(mode, now, start, kev, cves, news, health, errors, late_note=None):
    """Return (text, included). `included` lists IDs actually shown, so only
    those are marked as seen after a successful post."""
    now_mt = now.astimezone(MT)
    start_mt = start.astimezone(MT)
    included = {"kev": [], "nvd": [], "news": []}
    kev_ids = {item["cveID"] for item in kev}

    # Section 1: KEV
    priority_kev, other_kev = [], []
    for item in kev:
        text = " ".join(
            item.get(k, "") for k in ("vendorProject", "product", "shortDescription")
        )
        (priority_kev if priority_hits(text) else other_kev).append(item)
    kev_lines, shown = [], 0
    for label, group in (("PRIORITY", priority_kev), ("OTHER", other_kev)):
        for item in group:
            if shown >= CAPS["kev"]:
                break
            extras = []
            if item.get("dueDate"):
                extras.append(f"due {item['dueDate']}")
            if str(item.get("knownRansomwareCampaignUse", "")).lower() == "known":
                extras.append("ransomware use: known")
            kev_lines.append(
                f"`KEV` *{label}* — {item['cveID']} | "
                f"{clean(item.get('vendorProject', ''))} {clean(item.get('product', ''))}"
                + (f" | {', '.join(extras)}" if extras else "")
                + f" | <https://nvd.nist.gov/vuln/detail/{item['cveID']}>"
            )
            included["kev"].append(item["cveID"])
            shown += 1
    _more(kev_lines, len(kev), shown)

    # Section 2: AI-enabled threat activity (includes CAIRN)
    ai_items = sorted(
        [n for n in news if n.flags & {"CAIRN", "AI-THREAT"}],
        key=lambda n: ("CAIRN" not in n.flags, -n.score, -n.published.timestamp()),
    )
    ai_lines = []
    for n in ai_items[: CAPS["ai"]]:
        label = "CAIRN" if "CAIRN" in n.flags else "AI-THREAT"
        ai_lines.append(
            f"`AI` *{label}* — [{clean(n.source, 40)}] {clean(n.title)} | <{n.link}>"
        )
        included["news"].append(norm_link(n.link))
    _more(ai_lines, len(ai_items), min(len(ai_items), CAPS["ai"]))

    # Section 3: NVD
    relevant = []
    for cve in cves:
        if cve["id"] in kev_ids:
            continue
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        hits = priority_hits(desc)
        sector = bool(_hits(SECTOR_RX, desc.lower()))
        if hits or sector:
            relevant.append((cve, desc, bool(hits)))
    relevant.sort(key=lambda x: not x[2])
    nvd_lines = []
    for cve, desc, is_priority in relevant[: CAPS["nvd"]]:
        label = "PRIORITY KEYWORD" if is_priority else "SECTOR TERM"
        nvd_lines.append(
            f"`CVE` *{label}* — {cve['id']} | {clean(desc, 160)} | "
            f"<https://nvd.nist.gov/vuln/detail/{cve['id']}>"
        )
        included["nvd"].append(cve["id"])
    _more(nvd_lines, len(relevant), min(len(relevant), CAPS["nvd"]))

    # Section 4: other reported news
    ai_ids = {id(n) for n in ai_items}
    rest = sorted(
        [n for n in news if id(n) not in ai_ids],
        key=lambda n: ("PRIORITY" not in n.flags, -n.score, -n.published.timestamp()),
    )
    news_lines = []
    for n in rest[: CAPS["news"]]:
        label = "PRIORITY" if "PRIORITY" in n.flags else (
            "SECTOR" if "SECTOR" in n.flags else "OTHER"
        )
        news_lines.append(
            f"`NEWS` *{label}* — [{clean(n.source, 40)}] {clean(n.title)} | <{n.link}>"
        )
        included["news"].append(norm_link(n.link))
    _more(news_lines, len(rest), min(len(rest), CAPS["news"]))

    total = len(kev_lines) + len(ai_lines) + len(nvd_lines) + len(news_lines)
    title = ":electric_plug: *Power / Critical-Infrastructure Cyber Brief*"

    if mode == "update" and total == 0 and not errors:
        return (
            f"{title}\n*Update* | {now:%Y-%m-%d %H:%M UTC} ({now_mt:%H:%M} MT)\n"
            f"No new items since {start_mt:%H:%M} MT.",
            included,
        )

    lines = [
        title,
        f"*Mode:* {mode.title()} | *Generated:* {now:%Y-%m-%d %H:%M UTC} ({now_mt:%H:%M} MT)",
        f"*Window:* {start:%Y-%m-%d %H:%M} to {now:%H:%M} UTC",
    ]
    if late_note:
        lines.append(late_note)
    lines += [
        "*Labels:* `KEV` = confirmed exploited vulnerability, `AI` = reported AI-related "
        "threat activity (vendor reports reflect only the vendor's own telemetry), "
        "`NEWS` = reported, not independently verified.",
        "",
        f"*1. NEW KEV: CONFIRMED EXPLOITED VULNERABILITIES ({len(kev)})*",
    ]
    lines += kev_lines or ["None in window."]
    if errors.get("kev"):
        lines.append(f":warning: KEV source unavailable ({errors['kev']})")

    lines += ["", f"*2. AI-ENABLED THREAT ACTIVITY AND CAIRN ({len(ai_items)})*"]
    lines += ai_lines or ["None in window."]

    lines += ["", f"*3. NEW OR MODIFIED RELEVANT NVD CVEs ({len(relevant)})*"]
    lines += nvd_lines or ["None in window."]
    if errors.get("nvd"):
        lines.append(f":warning: NVD source unavailable ({errors['nvd']})")

    lines += ["", f"*4. REPORTED CYBER NEWS ({len(rest)})*"]
    lines += news_lines or ["None in window."]

    if not PRIORITY_TERMS:
        lines += ["", ":warning: Set the `PRIORITY_KEYWORDS` repository variable."]

    failed = [h for h in health if not h["ok"]]
    ok_count = len(health) - len(failed)
    lines += ["", f"*Sources:* {ok_count}/{len(health)} feeds OK."]
    if failed:
        lines.append(
            "Failed: " + "; ".join(f"{clean(h['name'], 40)} ({h['error']})" for h in failed)
        )
    lines += [
        "",
        "*Caveats:* Keyword matches do not establish affected versions, deployment, "
        "exploitability, or operational impact. Verify priority items against CISA, "
        "NVD, vendor advisories, and credible incident reporting.",
    ]
    return "\n".join(lines), included


def chunk_text(text, limit=1900):
    chunks, current = [], ""
    for line in text.splitlines():
        if len(line) > limit - 5:
            line = line[: limit - 6] + "…"
        candidate = current + line + "\n"
        if len(candidate) > limit:
            chunks.append(current)
            current = line + "\n"
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def deliver_to_discord(text):
    webhook = os.getenv("DISCORD_WEBHOOK_URL")
    if not webhook:
        raise RuntimeError("DISCORD_WEBHOOK_URL secret is not set")
    if not webhook.startswith("https://discord.com/api/webhooks/"):
        raise RuntimeError("DISCORD_WEBHOOK_URL does not look like a Discord webhook URL")
    for chunk in chunk_text(text):
        for attempt in range(4):
            response = SESSION.post(
                webhook,
                json={"content": chunk, "allowed_mentions": {"parse": []}},
                timeout=20,
            )
            if response.status_code == 429:
                try:
                    wait = float(response.json().get("retry_after", 2))
                except ValueError:
                    wait = 2.0
                time.sleep(min(wait, 30))
                continue
            response.raise_for_status()
            break
        else:
            raise RuntimeError("Discord rate limit did not clear after 4 attempts")
        time.sleep(0.4)


# --------------------------------------------------------------------------
# Run modes
# --------------------------------------------------------------------------


def write_summary(markdown):
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")


def check_feeds():
    rows = []
    for feed in load_feeds():
        status, count, newest = "OK", 0, "-"
        try:
            entries = fetch_feed(feed)
            count = len(entries)
            times = [t for t in (entry_time(e) for e in entries) if t]
            newest = max(times).strftime("%Y-%m-%d") if times else "-"
        except Exception as error:  # noqa: BLE001
            status = f"FAIL ({short_error(error)})"
        enabled = "yes" if feed.get("enabled", True) else "no"
        rows.append((feed["name"], enabled, status, count, newest))
    try:
        kev_total = len(get_json(KEV_URL).get("vulnerabilities", []))
        rows.append(("CISA KEV JSON", "yes", "OK", kev_total, "-"))
    except Exception as error:  # noqa: BLE001
        rows.append(("CISA KEV JSON", "yes", f"FAIL ({short_error(error)})", 0, "-"))

    lines = ["| Feed | Enabled | Status | Entries | Newest |", "|---|---|---|---|---|"]
    lines += [f"| {n} | {e} | {s} | {c} | {t} |" for n, e, s, c, t in rows]
    table = "\n".join(lines)
    print(table)
    write_summary("### Feed health\n" + table)
    return 0


def parse_args(argv=None):
    env_true = lambda name: os.getenv(name, "").strip().lower() in ("1", "true", "yes")
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--mode",
        choices=["auto", "morning", "update"],
        default=os.getenv("BRIEFING_MODE", "auto") or "auto",
    )
    parser.add_argument("--dry-run", action="store_true", default=env_true("DRY_RUN"))
    parser.add_argument("--check-feeds", action="store_true", default=env_true("CHECK_FEEDS"))
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    now = utcnow()
    now_mt = now.astimezone(MT)

    if args.check_feeds:
        return check_feeds()

    state = load_state()
    use_state = args.mode == "auto"
    record = use_state and not args.dry_run
    late_note = None

    if args.mode == "auto":
        due = due_modes(now_mt, state)
        if not due:
            print(f"Nothing due at {now_mt:%Y-%m-%d %H:%M} MT. "
                  "Use mode morning or update to preview.")
            return 0
        mode, superseded = due[0], due[1:]
        lateness = now_mt - slot_time(now_mt, mode)
        if lateness > LATE_AFTER and os.getenv("GITHUB_EVENT_NAME") != "workflow_dispatch":
            late_note = (
                f":hourglass: *Delayed run:* scheduled {slot_time(now_mt, mode):%H:%M} MT, "
                f"generated {now_mt:%H:%M} MT ({fmt_delta(lateness)} late)."
            )
    else:
        mode, superseded = args.mode, []

    start = window_start(mode, now, state, use_state)
    feeds = load_feeds()
    news, health = collect_news(feeds, start, now)
    errors = {}
    try:
        kev = fetch_kev(start)
    except Exception as error:  # noqa: BLE001
        kev, errors["kev"] = [], short_error(error)
    try:
        cves = nvd_cves(start, now)
    except Exception as error:  # noqa: BLE001
        cves, errors["nvd"] = [], short_error(error)

    if errors.get("kev") and errors.get("nvd") and not any(h["ok"] for h in health):
        print("Every data source failed. Not posting an empty brief.", file=sys.stderr)
        return 1

    if use_state:
        seen = state["seen"]
        kev = [k for k in kev if k["cveID"] not in seen["kev"]]
        cves = [
            c for c in cves
            if c["id"] not in seen["nvd"] and c["id"] not in seen["kev"]
        ]
        news = [n for n in news if norm_link(n.link) not in seen["news"]]

    text, included = build_brief(mode, now, start, kev, cves, news, health, errors, late_note)

    if args.dry_run:
        print(text)
        write_summary("### Dry run brief\n```\n" + text + "\n```")
        return 0

    deliver_to_discord(text)

    if record:
        today = now_mt.date().isoformat()
        day = state["posted"].setdefault(today, {})
        day[mode] = now.isoformat()
        for skipped in superseded:
            day[skipped] = "superseded"
        stamp = today
        for kind, ids in included.items():
            for item_id in ids:
                state["seen"][kind][item_id] = stamp
        state["last_post_utc"] = now.isoformat()
        save_state(state, now)
    return 0


if __name__ == "__main__":
    sys.exit(main()) 
