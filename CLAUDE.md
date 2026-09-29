# spur-saas-log-enrichment

Detects anonymising VPN/proxy and watchlisted IPs across Slack, Zoom, Teamtailor and Okta
logs, and posts new findings to Slack. `slack_alert_cron.py` runs every 30 minutes.

**Read `AGENTS.md` before running anything.** It has the rules for one-off checks — which
files must never be written by hand, why a Teamtailor false positive is worse than a missed
detection, and the collision gate to run before adding to `data.csv`.

Read `README.md` for configuration and the data sources.
