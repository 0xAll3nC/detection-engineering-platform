"""
Drive Invoke-AtomicRedTeam on the Windows victim over WinRM.

Status: Phase 4 scaffold. Not yet execution-tested against the lab.
Known gaps tracked for Phase 4: execution success is not verified beyond the
WinRM status code, prerequisites (-GetPrereqs) are not fetched, and tests
are selected by number rather than by auto_generated_guid.

Prerequisites on the victim: Invoke-AtomicRedTeam installed, WinRM reachable
from the orchestrator (NTLM over an isolated host-only network; see
docs/SETUP.md), and a local admin account.

Requires the optional `lab` extra (pywinrm); imported lazily so unit tests
and simulated runs do not need it.
"""

from __future__ import annotations

from dataclasses import dataclass

from detection_platform.config import VictimSettings


@dataclass
class AtomicResult:
    technique_id: str
    test_numbers: list[int] | None
    status_code: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.status_code == 0


class AtomicRunner:
    def __init__(self, settings: VictimSettings | None = None):
        import winrm  # optional dependency: pip install '.[lab]'

        s = settings or VictimSettings.from_env()
        self.session = winrm.Session(s.host, auth=(s.username, s.password), transport=s.transport)

    def _invoke(self, technique_id: str, test_numbers: list[int] | None, extra: str = ""):
        test_arg = f"-TestNumbers {','.join(str(n) for n in test_numbers)}" if test_numbers else ""
        script = f"Invoke-AtomicTest {technique_id} {test_arg} {extra} -Confirm:$false"
        result = self.session.run_ps(script)
        return AtomicResult(
            technique_id=technique_id,
            test_numbers=test_numbers,
            status_code=result.status_code,
            stdout=_decode(result.std_out),
            stderr=_decode(result.std_err),
        )

    def run_technique(self, technique_id: str, test_numbers: list[int] | None = None):
        """Run numbered atomic tests. test_numbers=None runs ALL tests (avoid)."""
        return self._invoke(technique_id, test_numbers)

    def cleanup_technique(self, technique_id: str, test_numbers: list[int] | None = None):
        return self._invoke(technique_id, test_numbers, extra="-Cleanup")


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)
