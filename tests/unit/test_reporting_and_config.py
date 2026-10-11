from __future__ import annotations

import json

import pytest

from detection_platform.cli import main
from detection_platform.config import ConfigError, WazuhIndexerSettings
from detection_platform.reporting.navigator import build_layer
from tests.conftest import FIXTURES_DIR

SIMULATED = FIXTURES_DIR / "reporting" / "simulated_results.json"


def _set_env(monkeypatch, **values):
    for key, value in values.items():
        monkeypatch.setenv(f"WAZUH_INDEXER_{key}", value)


def test_simulated_layer_is_labelled_as_simulated():
    layer = build_layer({"T1087.001": "detected"}, name="x", description="", simulated=True)
    assert layer["name"].startswith("SIMULATED")
    assert "NOT VALIDATION EVIDENCE" in layer["description"]


def test_layer_uses_behaviour_language_not_coverage():
    layer = build_layer({"T1087.001": "detected", "T1003.001": "missed"}, "x", "")
    assert "1/2 selected ATT&CK-mapped behaviours detected" in layer["description"]
    assert "coverage" not in json.dumps(layer).lower()


def test_cli_simulated_validation_writes_labelled_outputs(tmp_path):
    assert main(["validate", "--simulate", str(SIMULATED), "--out", str(tmp_path)]) == 0
    layer = json.loads((tmp_path / "navigator_layer.json").read_text())
    assert layer["name"].startswith("SIMULATED")
    assert {t["techniqueID"] for t in layer["techniques"]} >= {"T1087.001"}


def test_indexer_settings_verify_tls_by_default(monkeypatch):
    _set_env(monkeypatch, URL="https://h:9200/", USER="u", PASS="s3cr3t-value")
    monkeypatch.delenv("WAZUH_INDEXER_VERIFY_TLS", raising=False)
    monkeypatch.delenv("WAZUH_INDEXER_CA_BUNDLE", raising=False)
    s = WazuhIndexerSettings.from_env()
    assert s.requests_verify is True
    assert s.url == "https://h:9200"
    assert s.index_pattern == "wazuh-archives-*"
    assert "s3cr3t-value" not in repr(s)


def test_indexer_settings_ca_bundle_and_explicit_opt_out(monkeypatch):
    _set_env(monkeypatch, URL="https://h", USER="u", PASS="p", CA_BUNDLE="/ca.pem")
    assert WazuhIndexerSettings.from_env().requests_verify == "/ca.pem"
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "false")
    assert WazuhIndexerSettings.from_env().requests_verify is False


def test_missing_settings_raise_config_error(monkeypatch):
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    with pytest.raises(ConfigError):
        WazuhIndexerSettings.from_env()
