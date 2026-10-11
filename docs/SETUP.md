# Lab setup

The repository (rules, tests, compiler, orchestrator) runs anywhere. Live
validation needs your own lab: a Wazuh server and a Windows victim VM. Set them
up once; everything else talks to them through environment variables
(`.env.example`).

> **Isolation.** The victim exists to run attacker techniques. Keep it on a
> host-only / isolated virtual network, snapshot it before validation runs, and
> never expose WinRM or the Wazuh indexer beyond the lab.

## 1. Wazuh server (Docker, single node)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.6
cd wazuh-docker/single-node/
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
docker compose ps        # all services healthy after a minute or two
```

Change the default `admin` password immediately.

### Enable raw archive indexing (required — ADR-0002)

1. Manager `ossec.conf`: set `<logall_json>yes</logall_json>` in `<global>`.
2. Filebeat on the manager: enable archives in the Wazuh module
   (`archives: enabled: true`).
3. Restart the manager. In the dashboard, create an index pattern for
   `wazuh-archives-*` and confirm documents arrive.

### TLS for the client

Copy the stack's root CA (`config/wazuh_indexer_ssl_certs/root-ca.pem` in
wazuh-docker) somewhere outside the repository and set
`WAZUH_INDEXER_CA_BUNDLE` to its path. TLS verification is on by default; do
not disable it to work around the self-signed certificate.

## 2. Windows victim VM

Windows 10/11 or Server on VMware / VirtualBox / Hyper-V with line of sight to
the manager (TCP 1514/1515).

**a) Sysmon** (the telemetry the rules use)

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml   # e.g. olafhartong/sysmon-modular
```

**b) Wazuh agent**

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<manager_ip>" WAZUH_AGENT_NAME="<agent-name>"
NET START WazuhSvc
```

Collect the Sysmon channel — add to
`C:\Program Files (x86)\ossec-agent\ossec.conf` inside `<ossec_config>`, then
restart the service:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Check: run `whoami /all` and confirm a Sysmon EID 1 document in
`wazuh-archives-*` with `data.win.eventdata.commandLine`.

**c) WinRM** (for automated execution, Phase 4)

The client authenticates with **NTLM** (`ATOMIC_VICTIM_TRANSPORT=ntlm`), which
does not require Basic authentication or unencrypted transport:

```powershell
Enable-PSRemoting -Force
# Restrict the listener to the isolated lab network:
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress <orchestrator_ip>
```

Do **not** enable `Basic` auth or `AllowUnencrypted`. If you need encryption
beyond NTLM message sealing, configure an HTTPS listener.

**d) Invoke-AtomicRedTeam**

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Before mapping a test, read its definition (`Invoke-AtomicTest <T-ID> -ShowDetails`)
and record its `auto_generated_guid` in `validation/mappings.yml` (ADR-0006).

## 3. Point the repository at the lab

```bash
cp .env.example .env     # fill in; .env is gitignored
uv sync --extra lab
uv run detplat compile
uv run detplat validate --live          # Phase 4 scaffold; refuses unverified mappings
```

Raw output from live runs can contain hostnames, usernames and telemetry. Keep
it outside the repository and commit only sanitised records under
`docs/validation/`.
