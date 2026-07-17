# Aegis

**One patch process for every machine — Windows, Linux, macOS — as a bolt-on to Wazuh.**

Aegis keeps a fleet current and protects line-of-business apps from blind upgrades. It carries
**no fleet-specific data**: a machine learns *who it is* from its Wazuh agent label, so this repo
is a generic engine you can drop onto any Wazuh-managed estate.

## How it works
1. Each agent gets a Wazuh label `aegis.role` (set per **group** in the manager's shared config).
2. Aegis reads that label locally → maps it to a policy in [`roles.json`](roles.json) → runs the
   platform patch engine with the right scope + reboot behavior.
3. Every run writes a JSON line to the Aegis app-log for the SIEM to ship, monitor, and alert on.

Roles are generic — `personal`, `workstation`, `clinical`, `server`, `mac`, `linux`. The mapping of
*which machine is which role* lives only in your Wazuh manager, never here.

## Components
| File | Role |
|---|---|
| `aegis.ps1` / `aegis.sh` | the engine — reads the label, applies the role policy, invokes the patcher |
| `roles.json` | generic role → policy (scope, reboot behavior) |
| `patch-windows.ps1` | winget (apps) + PSWindowsUpdate (OS), SYSTEM-safe |
| `patch-linux.sh` | apt / dnf |
| `patch-mac.sh` | softwareupdate + Homebrew |
| `bootstrap.ps1` / `bootstrap.sh` | one-time installer (bolts onto an existing Wazuh agent) |

## Install
Aegis rides on the Wazuh agent — install/enroll the agent first, then bootstrap. **Pin a tag/commit**
in production and verify checksums (`SHA256SUMS`).

**1. On the Wazuh manager (once)** — creates the role groups + labels, the Active-Response command, and
app-log ingestion. Run **on the server**:
```bash
curl -fsSL https://raw.githubusercontent.com/veteranop/Aegis/main/server-setup.sh | sudo bash
```

**2. On each agent** — bolts Aegis on + enables `remote_commands`:

**Windows** (Administrator):
```powershell
$env:AEGIS_REF='main'
irm "https://raw.githubusercontent.com/veteranop/Aegis/$($env:AEGIS_REF)/bootstrap.ps1" | iex
```
**Linux/macOS** (sudo):
```bash
export AEGIS_REF=main
curl -fsSL "https://raw.githubusercontent.com/veteranop/Aegis/$AEGIS_REF/bootstrap.sh" | sudo -E bash
```
> Public repo — no token needed. **Pin `AEGIS_REF` to a release tag** (not `main`) in production, and the bootstrap verifies `SHA256SUMS` before installing.

## Running
- **On-demand:** the Wazuh manager triggers `aegis` via Active Response (`PUT /active-response`).
- **Scheduled:** a Wazuh `wodle command` in the group's shared config.
- **Manual/test:** `aegis.ps1 -Role personal` (dry run) — the engine refuses to patch a machine it
  can't identify.

Aegis defaults to **dry run**; pass `-Apply` / `--apply` to actually patch.

## Security note
The Wazuh-triggered model requires `remote_commands` on agents, which makes the **manager a
command-execution root over the fleet**. Treat the manager as a crown-jewel host, harden its access,
and monitor the Aegis app-log in your SIEM. Prefer a **private** repo + pinned, checksum-verified
installs.

## License
See [LICENSE](LICENSE).
