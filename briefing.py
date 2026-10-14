import os
import smtplib
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import feedparser
import requests

NOW = datetime.now(timezone.utc)
START = NOW - timedelta(hours=30)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    "develop/known_exploited_vulnerabilities.json"
)
NEWS_FEEDS = {
    "SecurityWeek": "https://www.securityweek.com/feed/",
}

# Replace with YOUR vendors/products. Broad terms are for news, not proof of exposure.
ASSETS = [
    x.strip().lower()
    for x in os.getenv("ASSET_KEYWORDS", "").split(",")
    if x.strip()
]
SECTOR_TERMS = (
    "electric utility", "power grid", "substation", "electricity",
    "industrial control", "operational technology", "scada",
    "energy sector", "power plant",
)
NEWS_TERMS = SECTOR_TERMS + (
    "zero-day", "zero day", "ransomware", "exploited",
    "cyberattack", "cyber attack", "ai cyber", "ai security",
)
session = requests.Session()
session.headers["User-Agent"] = "power-cyber-briefing/0.1 (contact: operator)"


def get_json(url, params=None, headers=None):
    for attempt in range(3):
        try:
            response = session.get(
                url, params=params, headers=headers, timeout=40
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def nvd_cves():
    params = {
        "lastModStartDate": START.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
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
        time.sleep(6)  # Conservative pacing for NVD.
    return results


def kev_additions():
    data = get_json(KEV_URL)
    return [
        item for item in data["vulnerabilities"]
        if datetime.strptime(
            item["dateAdded"], "%Y-%m-%d"
        ).replace(tzinfo=timezone.utc) >= (
            START - timedelta(days=1)
        ).replace(hour=0, minute=0, second=0, microsecond=0)
    ]


def news():
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
            if published >= START and any(term in text for term in NEWS_TERMS):
                items.append((source, entry.get("title", ""), entry.get("link", "")))
    return items


def matched_terms(text):
    lower = text.lower()
    return [term for term in ASSETS if term in lower]


def build_brief(kev, cves, stories):
    lines = [
        f"U.S. power/OT cyber briefing — {NOW:%Y-%m-%d %H:%M UTC}",
        f"Window: approximately {START:%Y-%m-%d %H:%M}–{NOW:%H:%M} UTC",
        "Labels: KEV = confirmed exploited vulnerability; "
        "news = reported, not independently verified.",
        "",
        f"NEW KEV ENTRIES ({len(kev)})",
    ]
    for item in kev[:20]:
        label = f"{item['vendorProject']} {item['product']}"
        hits = matched_terms(label + " " + item.get("shortDescription", ""))
        lines.append(
            f"- {item['cveID']} | {label} | added {item['dateAdded']}"
            f" | asset keyword: {', '.join(hits) if hits else 'none'}"
            f" | https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        )

    relevant = []
    for cve in cves:
        desc = next(
            (d["value"] for d in cve.get("descriptions", [])
             if d.get("lang") == "en"),
            "",
        )
        hits = matched_terms(desc)
        sector = any(term in desc.lower() for term in SECTOR_TERMS)
        if hits or sector:
            relevant.append((cve, desc, hits, sector))

    relevant.sort(key=lambda x: (not bool(x[2]), not x[3]))
    lines += ["", f"NEW OR MODIFIED RELEVANT CVEs ({len(relevant)})"]
    for cve, desc, hits, sector in relevant[:25]:
        lines.append(
            f"- {cve['id']} | {'ASSET KEYWORD' if hits else 'SECTOR TERM'}"
            f" | {desc[:170]} | https://nvd.nist.gov/vuln/detail/{cve['id']}"
        )

    lines += ["", f"REPORTED CYBER/AI-CYBER NEWS ({len(stories)})"]
    for source, title, link in stories[:20]:
        lines.append(f"- [{source}] {title} | {link}")

    if not ASSETS:
        lines += ["", "Configure ASSET_KEYWORDS to identify your products."]
    lines += [
        "",
        "Keyword matches do not establish affected versions, deployment, "
        "exploitability, or operational impact. Verify against primary sources."
    ]
    return "\n".join(lines)


def deliver(text):
    destinations = 0
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if webhook:
        # Split to keep individual Slack messages manageable.
        chunks, current = [], ""
        for line in text.splitlines():
            if len(current) + len(line) > 3500:
                chunks.append(current)
                current = ""
            current += line + "\n"
        if current:
            chunks.append(current)
        for chunk in chunks:
            response = session.post(
                webhook, json={"text": chunk}, timeout=20
            )
            response.raise_for_status()
        destinations += 1

    if os.getenv("SMTP_HOST"):
        msg = EmailMessage()
        msg["Subject"] = f"Power/OT cyber briefing — {NOW:%Y-%m-%d}"
        msg["From"] = os.environ["EMAIL_FROM"]
        msg["To"] = os.environ["EMAIL_TO"]
        msg.set_content(text)
        with smtplib.SMTP(
            os.environ["SMTP_HOST"],
            int(os.getenv("SMTP_PORT", "587")),
            timeout=30,
        ) as smtp:
            smtp.starttls()
            smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(msg)
        destinations += 1

    if not destinations:
        raise RuntimeError("Set SLACK_WEBHOOK_URL and/or SMTP settings")


if __name__ == "__main__":
    brief = build_brief(kev_additions(), nvd_cves(), news())
    deliver(brief)

