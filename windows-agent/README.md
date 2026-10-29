# Windows remote-assist agent

Two .NET 8 projects:

- **`SentinelRemoteAssist/`** — the support agent. Enrollment, control channel,
  reverse SSH support tunnel, endpoint hardening (WDAC/AppLocker, SRP, Windows Update
  control, EDR hooks), optional S3/R2 network drive.
- **`NukeAgent/`** — a small secure-wipe utility invoked by the agent.

PowerShell helpers at the repository root of this directory cover hardening, SRP
deployment, and debloating.

## Build

Requires the .NET 8 SDK on Windows 10/11.

```powershell
dotnet build SentinelRemoteAssist/SentinelRemoteAssist.csproj -c Release
dotnet build NukeAgent/NukeAgent.csproj -c Release
```

Runtime assets are **not committed** and are embedded only when present:

| Asset | Purpose |
| :--- | :--- |
| `SentinelRemoteAssist/rclone.exe` | S3/R2 network drive (optional). |
| `SentinelRemoteAssist/xray.exe` | REALITY transport (optional). |
| `SentinelRemoteAssist/OpenSSH-Win64.zip` | Bundled OpenSSH for the support tunnel. |
| `sentinel-setup.ps1.gz` / `sentinel-uninstall.ps1.gz` | Generated from the `.ps1` sources. |

Build a full installer only after placing those files.

## Configuration

Read from the environment at runtime:

| Variable | Purpose |
| :--- | :--- |
| `SENTINEL_SERVER_URL` | Control server base URL. |
| `SENTINEL_BASTION_HOST` | Bastion host for the Hop-1 `HostKeyAlias`. |
| `SENTINEL_BASTION_KNOWN_HOSTS` | Pinned `[host]:port ssh-ed25519 ...` line. |
| `SENTINEL_REALITY_NODES` / `_V6` / `_SNIS` | REALITY node and SNI lists. |
| `SENTINEL_REALITY_PUBLIC_KEY` / `_SHORT_ID` / `_CONTROL_UUID` | REALITY credentials. |

Empty REALITY values disable the tunnel and fall back to a direct connection. See
[`../docs/CONFIGURATION.md`](../docs/CONFIGURATION.md).

The bastion server itself is **not** part of this repository. Point the agent at a
compatible bastion you operate.

## License

AGPL-3.0. See [`../LICENSE`](../LICENSE).
