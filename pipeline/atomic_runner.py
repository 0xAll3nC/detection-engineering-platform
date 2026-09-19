"""
atomic_runner.py
-----------------
Drives Invoke-AtomicRedTeam on the Windows victim VM over WinRM, so the
purple team runner (running from your Linux/orchestrator host) can kick
off real attacker technique executions and know exactly when they ran.

Prerequisites on the Windows victim VM:
    - Invoke-AtomicRedTeam PowerShell module installed
      (https://github.com/redcanaryco/invoke-atomicredteam)
    - WinRM enabled and reachable from wherever this script runs
      (quick lab setup: `winrm quickconfig` as admin on the victim, and an
      account with local admin rights for pywinrm to authenticate as)
    - Atomics content present at the module's default path (or pass
      -PathToAtomicsFolder explicitly if you keep it elsewhere)

NOTE ON VERIFICATION: written against the documented pywinrm API
(winrm.Session / run_ps), but not execution-tested here since this sandbox
has no Windows host to WinRM into. Test against your real lab VM first --
this is the piece most likely to need small fixes for your specific
Windows/WinRM/auth setup (NTLM vs Kerberos vs Basic, HTTPS listener, etc).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


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
    def __init__(
        self,
        host: str | None = None,
        username: str | None = None,
        password: str | None = None,
        transport: str = "ntlm",
    ):
        import winrm  # imported lazily so --simulate mode doesn't need pywinrm installed

        host = host or os.environ["ATOMIC_VICTIM_HOST"]
        username = username or os.environ["ATOMIC_VICTIM_USER"]
        password = password or os.environ["ATOMIC_VICTIM_PASS"]
        self.session = winrm.Session(host, auth=(username, password), transport=transport)

    def run_technique(
        self, technique_id: str, test_numbers: list[int] | None = None
    ) -> AtomicResult:
        """Run one or more numbered atomic tests for a technique.

        test_numbers=None runs ALL tests defined for the technique, which
        can be noisy/slow and may include destructive tests -- prefer
        passing explicit test_numbers from pipeline/technique_test_map.yml
        once you've reviewed what each numbered test actually does.
        """
        test_arg = (
            f"-TestNumbers {','.join(str(n) for n in test_numbers)}" if test_numbers else ""
        )
        ps_script = f"Invoke-AtomicTest {technique_id} {test_arg} -Confirm:$false"
        result = self.session.run_ps(ps_script)
        return AtomicResult(
            technique_id=technique_id,
            test_numbers=test_numbers,
            status_code=result.status_code,
            stdout=_decode(result.std_out),
            stderr=_decode(result.std_err),
        )

    def cleanup_technique(self, technique_id: str, test_numbers: list[int] | None = None) -> AtomicResult:
        """Run the -Cleanup pass so the victim VM doesn't accumulate artifacts test after test."""
        test_arg = (
            f"-TestNumbers {','.join(str(n) for n in test_numbers)}" if test_numbers else ""
        )
        ps_script = f"Invoke-AtomicTest {technique_id} {test_arg} -Cleanup -Confirm:$false"
        result = self.session.run_ps(ps_script)
        return AtomicResult(
            technique_id=technique_id,
            test_numbers=test_numbers,
            status_code=result.status_code,
            stdout=_decode(result.std_out),
            stderr=_decode(result.std_err),
        )


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)
