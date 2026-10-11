"""
wazuh_client.py
----------------
Thin client for Wazuh's Indexer (OpenSearch-based, Wazuh 4.x+) alert
search API. Used by purple_team_runner.py to check whether a detection
rule actually fired during a given time window after a purple team test
was executed.

We query using the exact compiled Lucene query string produced by
compile_rules.py -- this directly ties the purple team validation back to
the detection-as-code pipeline rather than maintaining a second, separate
set of "is this alert real" logic.

Auth/connection details come from environment variables so credentials
never end up in the repo:
    WAZUH_INDEXER_URL   e.g. https://localhost:9200
    WAZUH_INDEXER_USER  e.g. admin
    WAZUH_INDEXER_PASS
    WAZUH_INDEXER_VERIFY_TLS  "true"/"false" (default: false, since the
                               default Wazuh single-node lab setup uses a
                               self-signed cert)

WHY WE SEARCH wazuh-archives-* AND NOT wazuh-alerts-*: Wazuh's manager
only writes to wazuh-alerts-* when its OWN built-in ruleset decides an
event is alert-worthy. Our Sigma rules are a separate, independent
detection layer -- we don't want their fate to depend on whether Wazuh's
stock ruleset happened to also flag the same event. So we run our
compiled queries against the archives index instead, which holds every
event Sysmon shipped, regardless of whether Wazuh's own rules fired on
it. This requires <logall_json>yes</logall_json> enabled on the manager
and the Filebeat archives module turned on (see docs/SETUP.md) -- without
that, wazuh-archives-* simply won't exist or will be empty.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import requests


class WazuhClient:
    def __init__(
        self,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool | None = None,
        index_pattern: str = "wazuh-archives-*",
    ):
        self.base_url = (base_url or os.environ["WAZUH_INDEXER_URL"]).rstrip("/")
        self.username = username or os.environ["WAZUH_INDEXER_USER"]
        self.password = password or os.environ["WAZUH_INDEXER_PASS"]
        if verify_tls is None:
            verify_tls = os.environ.get("WAZUH_INDEXER_VERIFY_TLS", "false").lower() == "true"
        self.verify_tls = verify_tls
        self.index_pattern = index_pattern

    def search_alerts(
        self,
        lucene_query: str,
        start_time: datetime,
        end_time: datetime,
        timestamp_field: str = "@timestamp",
        size: int = 50,
    ) -> list[dict]:
        """Return raw alert documents matching lucene_query within the time window."""
        url = f"{self.base_url}/{self.index_pattern}/_search"
        body = {
            "size": size,
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": lucene_query}}],
                    "filter": [
                        {
                            "range": {
                                timestamp_field: {
                                    "gte": start_time.astimezone(timezone.utc).isoformat(),
                                    "lte": end_time.astimezone(timezone.utc).isoformat(),
                                }
                            }
                        }
                    ],
                }
            },
        }
        resp = requests.post(
            url,
            json=body,
            auth=(self.username, self.password),
            verify=self.verify_tls,
            timeout=30,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]

    def rule_fired(
        self, lucene_query: str, start_time: datetime, end_time: datetime
    ) -> bool:
        return len(self.search_alerts(lucene_query, start_time, end_time, size=1)) > 0
