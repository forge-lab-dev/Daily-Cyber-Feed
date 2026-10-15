import os
import time
from datetime import datetime, timedelta, timezone

import feedparser
import requests

NOW = datetime.now(timezone.utc)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)
NEWS_FEEDS = {
    "SecurityWeek": "https://www.securityweek.com/feed/",
}

PRIORITY_TERMS = [
    x.strip().lower()
    for x in os.getenv("ASSET_KEYWORDS", "").split(",")
    if x.strip()
]

SECTOR_TERMS = [
    "electric utility", "power grid", "substation", "electricity",
    "industrial control", "operational technology", "scada",
    "energy sector", "power plant", "transmission", "distribution utility",
    "data center",
]

NEWS_TERMS = PRIORITY_TERMS + SECTOR_TERMS + [
    "zero-day", "zero day", "ransomware", "exploited", "cyberattack",
    "cyber attack", "ai cyber", "ai security", "critical infrastructure",
]

session = requests.Session()
session.headers["User-Agent"] = "power-cyber-briefing/0.2"


def get_json(url, params=None, headers=None):
    last_error = None
    for attempt in range(3):
        try:
            response = session.get(
                url, params=params, headers=headers, timeout=40
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as error:
            last_error = error
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Request failed: {url}") from last_error


def lookback_hours():
    return 2 if os.getenv("BRIEFING_MODE", "morning") == "update" else 36


def nvd_cves(start):
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "startIndex": 0,
    }
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    results = []
    while True:
        data = get_json(NVD_URL, params=params, headers=headers)
        results.extend(item["cve"] for item in data["vulnerabilities"])
        params["startIndex"] += data["resultsPerPage"]
        if params["startIndex"] >= data["totalResults"]:
            break
        time.sleep(6)
    return results


def kev_additions(start):
    data = get_json(KEV_URL)
    day_start = start.replace(hour=0, minute=0, second=0, microsecond=0)
    return [
        item for item in data["vulnerabilities"]
        if datetime.strptime(
            item["dateAdded"], "%Y-%m-%d"
        ).replace(tzinfo=timezone.utc) >= day_start
    ]


def news(start):
    items = []
    for source, url in NEWS_FEEDS.items():
        feed = feedparser.parse(url)
        if feed.bozo and not feed.entries:
            raise RuntimeError(f"Could not read {source} feed")
        for entry in feed.entries:
            stamp = entry.get("published_parsed") or entry.get("updated_parsed")
            if not stamp:
                continue
            published = datetime.fromtimestamp(
                time.mktime(stamp), timezone.utc
            )
            text = f"{entry.get('title', '')} {entry.get('summary', '')}".lower()
            if published >= start and any(term in text for term in NEWS_TERMS):
                items.append((source, entry.get("title", ""), entry.get("link", "")))
    return items


def priority_hits(text):
    lower = text.lower()
    return [term for term in PRIORITY_TERMS if term in lower]


def build_brief(kev, cves, stories):
    mode = os.getenv("BRIEFING_MODE", "morning")
    start = NOW - timedelta(hours=lookback_hours())

    lines = [
        f":electric_plug: *Power / Critical-Infrastructure Cyber Brief*",
        f"*Mode:* {mode.title()} | *Generated:* {NOW:%Y-%m-%d %H:%M UTC}",
        f"*Window:* approximately {start:%Y-%m-%d %H:%M}–{NOW:%H:%M} UTC",
        "*Labels:* `KEV` = confirmed exploited vulnerability; "
        "`NEWS` = reported, not independently verified.",
        "",
        f"*1. NEW KEV — CONFIRMED EXPLOITED VULNERABILITIES ({len(kev)})*",
    ]

    priority_kev, normal_kev = [], []
    for item in kev:
        text = " ".join([
            item.get("vendorProject", ""), item.get("product", ""),
            item.get("shortDescription", ""),
        ])
        (priority_kev if priority_hits(text) else normal_kev).append(item)

    for label, group in (("PRIORITY", priority_kev), ("OTHER", normal_kev)):
        for item in group[:20]:
            lines.append(
                f"`KEV` *{label}* — {item['cveID']} | "
                f"{item.get('vendorProject', '')} {item.get('product', '')} | "
                f"added {item['dateAdded']} | "
                f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            )

    relevant = []
    for cve in cves:
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        hits = priority_hits(desc)
        sector = any(term in desc.lower() for term in SECTOR_TERMS)
        if hits or sector:
            relevant.append((cve, desc, hits, sector))

    relevant.sort(key=lambda x: (not bool(x[2]), not x[3]))
    lines += ["", f"*2. NEW OR MODIFIED RELEVANT NVD CVEs ({len(relevant)})*"]
    for cve, desc, hits, sector in relevant[:25]:
        label = "PRIORITY KEYWORD" if hits else "SECTOR TERM"
        lines.append(
            f"`CVE` *{label}* — {cve['id']} | {desc[:160]} | "
            f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
        )

    priority_news, normal_news = [], []
    for source, title, link in stories:
        text = f"{title} {link}"
        (priority_news if priority_hits(text) else normal_news).append(
            (source, title, link)
        )

    lines += ["", f"*3. REPORTED CYBER / AI-CYBER NEWS ({len(stories)})*"]
    for label, group in (("PRIORITY", priority_news), ("OTHER", normal_news)):
        for source, title, link in group[:20]:
            lines.append(f"`NEWS` *{label}* — [{source}] {title} | {link}")

    if not PRIORITY_TERMS:
        lines += ["", ":warning: Set the `PRIORITY_KEYWORDS` repository variable."]

    lines += [
        "",
        "*Caveats:* Keyword matches do not establish affected versions, "
        "deployment, exploitability, or operational impact. Verify priority "
        "items against CISA, NVD, vendor advisories, and credible incident reporting.",
    ]
    return "\n".join(lines)

def deliver_to_discord(text):
    webhook = os.getenv("DISCORD_WEBHOOK_URL")
    if not webhook:
        raise RuntimeError("DISCORD_WEBHOOK_URL secret is not set")

    if not webhook.startswith("https://discord.com/api/webhooks/"):
        raise RuntimeError(
            "DISCORD_WEBHOOK_URL does not look like a Discord webhook URL"
        )

    chunks = []
    current = ""
    for line in text.splitlines():
        candidate = current + line + "\n"
        if len(candidate) > 1900:
            chunks.append(current)
            current = line + "\n"
        else:
            current = candidate

    if current:
        chunks.append(current)

    for chunk in chunks:
        response = session.post(
            webhook,
            json={"content": chunk},
            timeout=20,
        )
        response.raise_for_status()

if __name__ == "__main__":
    start = NOW - timedelta(hours=lookback_hours())
    brief = build_brief(
        kev_additions(start),
        nvd_cves(start),
        news(start),
    )
    deliver_to_discord(brief)
