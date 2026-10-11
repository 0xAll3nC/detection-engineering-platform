"""Pinned MITRE ATT&CK data version.

pySigma's ATT&CK tag validator downloads the *latest* enterprise data by
default, so CI results could change without any change in this repository
(ATT&CK v19 removed the Defense Evasion tactic). Validation is pinned to an
explicit release; upgrading is a deliberate PR that re-validates all tags.
"""

from __future__ import annotations

ATTACK_VERSION = "19.2"
ATTACK_ENTERPRISE_URL = (
    "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)


def pin_pysigma_attack_data(url: str = ATTACK_ENTERPRISE_URL) -> None:
    from sigma.data import mitre_attack

    mitre_attack.set_url(url)
