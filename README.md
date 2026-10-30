# Daily-Cyber-Feed
This is a daily cyber feed from multiple sources including CISA, DOE CESER Cyber sources,  updates, etc. 
Added: CISA advisories and ICS advisories, Talos, Google Threat Intelligence, Microsoft Security, Unit 42, SentinelLabs, OpenAI, The Record, CyberScoop and the two CAIRN GitHub feeds. The Talos feed is also what carries CAIRN and CLOSEDQUORUM posts.
Anthropic has no RSS feed. A directory I checked says its feed address returns “not found”. I added a Google News query feed instead, which catches press coverage of AI-misuse reports. It is lower trust and is labeled that way.
DOE CESER has no feed I could find, even though your repo description mentions it.
Feed status. Most feed URLs are confirmed live only by a third-party directory (Feeder, checked Sept 27 to Oct 13), not from a GitHub runner. openai.com and cisa.gov may block datacenter IPs.
Guessed feeds. The Dragos and Industrial Cyber URLs are guesses and ship disabled.
CAIRN commits feed. It assumes the branch is named main. The CAIRN releases feed is expected to be empty, since the repo had no releases when I checked.

Before you merge
Diff my briefing.yml and requirements.txt against your current ones. I rebuilt them from memory of your repo. Confirm the secret names DISCORD_WEBHOOK_URL and NVD_API_KEY, and the PRIORITY_KEYWORDS variable.
Run the workflow manually with check_feeds ticked. Fix or disable any feed marked FAIL.
Run it again with dry_run ticked and read the brief.
Merge, then compare tomorrow’s “Generated” times against the 8:01 and 9:01 targets.
Scheduling and the heartbeat
Auto mode. briefing.py now decides what’s due from Mountain time and its saved state, instead of comparing the cron string. The old '0 9 * * *' check is gone, so changing the minute can’t break it. If a late run fires after 9, it posts the morning brief once and skips the redundant update.
State storage. State lives on a brief-state branch. This adds no new Actions, so your actions.lock stays valid. The branch is public if your repo is public, but it only holds CVE IDs and dates.
Heartbeat. It is a commented cron block in briefing.yml. To enable it, uncomment those two lines. It cannot double-post, and it cannot help if GitHub delays every scheduled run.
Safe testing. The manual “Run workflow” form now has dry_run (shows the brief in the job summary without posting) and check_feeds.

What changed
Feeds can’t kill the brief anymore. Each feed is fetched with a real timeout, and a failure shows up as a “Failed: name (reason)” line in the brief footer. The run only exits with an error if every source is down.
No repeated items. Seen CVEs and links are remembered for 14 days. Each brief covers the time since the last successful post instead of a fixed 36 or 2 hours.
Less noise. News items are scored with word-boundary matching, so “ai” no longer matches inside other words. I also removed “pipeline” from the sector terms, because it matched CI/CD stories.
AI-threat section. It is section 2 of the same brief, not a separate push. It includes anything flagged CAIRN.
Discord safety. Links no longer unfurl into big previews, and @everyone in a feed title can’t ping your channel.
Late-run notice. A delayed run prints “scheduled 08:00 MT, generated 13:20 MT (5h 20m late)” in the header.
Quiet empty updates. If nothing is new at 9 AM, the update is a single line, so silence never looks like a failure.
