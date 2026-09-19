# Lab Setup

This project's code (rules, tests, CI, compiler, orchestrator) all lives in
this repo and runs anywhere. The pieces below -- the Wazuh server and the
Windows victim VM -- are your own infrastructure and can't be shipped in
the repo. Set them up once, then everything else in this project talks to
them.

Rough time: 1-2 evenings for a first working end-to-end pass.

## 1. Wazuh server (Docker Compose, single node)

Runs fine on a laptop/desktop with Docker Desktop, or a small cloud VM
(4GB+ RAM recommended). This is the *official* Wazuh Docker Compose stack,
not a custom one.

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.6   # check the repo for the latest release tag
cd wazuh-docker/single-node/

# generate the TLS certs the stack needs (one-time)
docker compose -f generate-indexer-certs.yml run --rm generator

docker compose up -d
docker compose ps        # everything should show "healthy" after a minute or two
```

Dashboard: `https://<docker-host-ip>` (accept the self-signed cert warning).
Default login is `admin` / `SecretPassword` -- **change this immediately**,
this default is well-known and gets scanned for.

## 2. Windows victim VM

Any Windows 10/11 or Server VM works (VirtualBox, VMware, Hyper-V, or a
cloud Windows instance). Needs network line-of-sight to the Wazuh manager
(TCP 1514/1515) and, from wherever you run the purple team orchestrator,
WinRM reachability (TCP 5985).

**a) Install Sysmon** (this is what actually generates the rich
process/registry/network telemetry our rules key off):

1. Download Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
2. Grab a solid baseline config (don't run Sysmon config-less, the default
   logs almost nothing useful): https://github.com/olafhartong/sysmon-modular
   or the classic https://github.com/SwiftOnSecurity/sysmon-config
3. Install: `sysmon64.exe -accepteula -i sysmonconfig.xml`

**b) Install and enroll the Wazuh agent:**

1. Download the Windows agent MSI from your Wazuh dashboard
   (Agents management -> Deploy new agent -- it gives you a pre-filled
   install command with your manager's IP baked in), or run manually:
   ```powershell
   Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi -OutFile wazuh-agent.msi
   msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<manager_ip>" WAZUH_AGENT_NAME="win-victim-01"
   ```
2. Start it: `NET START WazuhSvc`
3. **Point the agent at the Sysmon event channel** -- this is the step
   people most often miss. Edit
   `C:\Program Files (x86)\ossec-agent\ossec.conf` and add inside
   `<ossec_config>`:
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
   Restart the service (`NET STOP WazuhSvc && NET START WazuhSvc`).
4. Confirm the agent shows "Active" in the Wazuh dashboard, and check
   Discover in the dashboard for incoming `data.win.eventdata.*` documents
   after triggering some activity (e.g. run `whoami /all`).

**c) Enable WinRM** (so the purple team orchestrator can remotely trigger
Atomic Red Team tests from your Linux/orchestrator machine):

```powershell
winrm quickconfig -q
Enable-PSRemoting -Force
# lab-only convenience; in anything beyond a throwaway lab, use HTTPS/Kerberos instead
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
```

**d) Install Invoke-AtomicRedTeam:**

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Sanity check from an elevated PowerShell prompt:
```powershell
Invoke-AtomicTest T1087.001 -TestNumbers 1
```
and confirm you see a matching alert land in Wazuh a few seconds later.

## 3. Point this repo at your lab

Set these before running anything in `--live` mode:

```bash
export WAZUH_INDEXER_URL="https://<docker-host-ip>:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASS="<your changed password>"

export ATOMIC_VICTIM_HOST="<windows-victim-ip>"
export ATOMIC_VICTIM_USER="<local admin username>"
export ATOMIC_VICTIM_PASS="<password>"
```

Then:
```bash
pip install -r requirements.txt
pytest tests/ -v                                    # rule logic (no infra needed)
python pipeline/compile_rules.py                     # compile rules -> Wazuh queries
python pipeline/purple_team_runner.py --live          # real purple team pass
```

If something in `compile_rules.py` or `atomic_runner.py` throws an API
error, see the notes at the top of those files -- they were written
against documented APIs but not execution-tested against a live pySigma
install or a real WinRM host, so some drift is plausible and worth fixing
as your first real checkpoint.
