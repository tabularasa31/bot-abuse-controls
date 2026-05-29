# antibot-analytics — daily BAC traffic analyzer + blocklist-candidate producer.
# Runs analyze.py against Loki (in-network) and writes JSON artifacts + emails
# the report. Deliberately minimal: python3 + msmtp only (no git/gh/go — turning
# artifacts into PRs is the host-side autopilot's job).
FROM python:3.12-slim

# msmtp for the daily email (Gmail SMTP, same as the old edge path);
# ca-certificates for TLS to Loki/SMTP; tzdata so report timestamps are local.
RUN apt-get update \
    && apt-get install -y --no-install-recommends msmtp ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

# PyYAML is optional in analyze.py (gates degrade without it); install it so the
# auxiliary catalog reads are available.
RUN pip install --no-cache-dir pyyaml

COPY entrypoint.sh run.sh /opt/analytics/
RUN chmod +x /opt/analytics/entrypoint.sh /opt/analytics/run.sh

ENTRYPOINT ["/opt/analytics/entrypoint.sh"]
