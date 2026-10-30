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
