"""
Thin client for the Wazuh indexer (OpenSearch-based, Wazuh 4.x) search API.

Validation runs the exact compiled Lucene query produced by sigma/compiler.py,
tying live validation to the detection-as-code pipeline instead of keeping a
second "is this alert real" implementation.

WHY wazuh-archives-* AND NOT wazuh-alerts-* (ADR-0002): the manager only
writes to wazuh-alerts-* when Wazuh's own ruleset decides an event is
alert-worthy, which would pre-filter telemetry before our Sigma validation.
wazuh-archives-* holds every event the agent shipped, which lets validation
tell "telemetry was absent" apart from "telemetry was present but the
detection did not match". Requires <logall_json>yes</logall_json> on the
manager and the Filebeat archives module enabled (docs/SETUP.md).

TLS verification is ON by default. For the lab's self-signed certificate,
point WAZUH_INDEXER_CA_BUNDLE at the Wazuh root CA rather than disabling
verification; WAZUH_INDEXER_VERIFY_TLS=false is an explicit opt-out.
"""

from __future__ import annotations

from datetime import UTC, datetime

import requests

from detection_platform.config import WazuhIndexerSettings


class WazuhClient:
    def __init__(self, settings: WazuhIndexerSettings | None = None):
        self.settings = settings or WazuhIndexerSettings.from_env()

    def search(
        self,
        lucene_query: str,
        start_time: datetime,
        end_time: datetime,
        timestamp_field: str = "@timestamp",
        size: int = 50,
    ) -> list[dict]:
        """Return raw documents matching lucene_query within the time window."""
        s = self.settings
        body = {
            "size": size,
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": lucene_query}}],
                    "filter": [
                        {
                            "range": {
                                timestamp_field: {
                                    "gte": start_time.astimezone(UTC).isoformat(),
                                    "lte": end_time.astimezone(UTC).isoformat(),
                                }
                            }
                        }
                    ],
                }
            },
        }
        resp = requests.post(
            f"{s.url}/{s.index_pattern}/_search",
            json=body,
            auth=(s.username, s.password),
            verify=s.requests_verify,
            timeout=30,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]

    def query_matched(self, lucene_query: str, start_time: datetime, end_time: datetime) -> bool:
        return len(self.search(lucene_query, start_time, end_time, size=1)) > 0
