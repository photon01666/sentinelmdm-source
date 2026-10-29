# Security model

## Purpose

SentinelMDM is a **self-hosted management and support platform**. It is designed for
deployments where the operator controls both the server and the devices, or where the
device user has given informed consent (for example a family device, a company-owned
laptop, or a managed support contract).

It is **not** a covert surveillance product. Features that can observe a person —
location, SMS, call logs, contacts, camera, microphone, screen capture, app usage — are
intended for transparent, lawful administration. If you cannot explain the deployment
to the device's user, you should not deploy it.

## Trust boundaries

| Boundary | What crosses it | Protection |
| :--- | :--- | :--- |
| Device → server | Telemetry, commands, enrollment | TLS; Socket.IO; optional REALITY/relay transport |
| Browser → server | Credentials, dashboard actions | TLS; session cookie; CSRF checks; WebAuthn/TOTP |
| Server → storage | Device records, uploads, backups | Encryption for sensitive fields; S3/R2 credentials |
| Operator → bastion → device | Support session | Reverse SSH with per-session keys; host-key pinning |

The **bastion is operator-run and out of scope** for this repository. A compromised
bastion is equivalent to a compromised support channel; harden and monitor it
accordingly.

## Enrollment and consent

1. The Android agent is installed as **Device Owner** through a provisioning flow
   (QR/NFC/ADB) that requires physical access to the device, or preinstalled as a
   system/privileged app in a custom ROM.
2. The agent obtains an enrollment ticket or account credentials.
3. The device is bound to the account; the server records the binding.

The Windows agent supports account-linked and ticket-based enrollment and shows the
Terms/MSA before installation. The Linux agent supports CLI credentials or a one-time
installer ticket.

**Consent is an operator responsibility.** The software provides the mechanism; it
cannot verify that your legal basis is valid.

## Android permissions and platform signing

The manifest requests high-risk permissions, including:

- location (foreground, background, fine/coarse);
- SMS, call logs, contacts, calendar;
- camera, microphone, screen capture (MediaProjection);
- app usage, package queries, notification access, accessibility;
- device administration, lock/wipe, app suspension, user management.

Several capabilities are declared `signature|privileged`. On a normal install these are
silently ignored. Full behaviour requires one of:

- platform signing with the ROM's platform key, or
- installation as a privileged app with the matching `privapp-permissions` allowlist
  (the GrapheneOS/AOSP integration is not part of this repository).

The stock build therefore runs in a reduced-permission mode. Do not assume that a
successful `assembleRelease` grants system-level capabilities.

## Data protection

- **In transit:** HTTPS/WSS. The agent can additionally wrap traffic in VLESS/REALITY
  via an embedded xray-core process when the network blocks direct connections.
- **At rest:** sensitive fields are encrypted by the server with deployment-supplied
  key material (`SERVER_ENC_KEY_PEM`, `ENC_PASSPHRASE`,
  `HWID_KEY`). Losing that material makes the affected data unrecoverable.
- **Backups:** database snapshots and OTA objects live in operator-controlled S3/R2
  buckets. Protect the credentials; they are read-write.
- **Zero-knowledge claims:** some flows are designed so the server does not hold the
  plaintext key for a payload class. This is not a blanket guarantee for every feature;
  review the encryption path for the data you care about.

## Authentication

- Passwords are stored as `bcrypt(PBKDF2-SHA256(password, per-user salt))`, so the
  plaintext is not passed directly to bcrypt. Legacy rows are upgraded on successful
  login.
- TOTP and WebAuthn/passkeys are supported.
- Sessions are cookie-based; set `COOKIE_INSECURE` only for local HTTP development.
- There are **no default credentials**. The server exits if `ADMIN_PASS` is unset.
- Login and TOTP endpoints are rate-limited; repeated failures should be alerted on.

## Remote assist

- The Windows and Linux agents open a **reverse SSH** connection to a bastion. The
  agent does not listen for inbound connections on the public internet.
- Hop-1 authenticates the device to the bastion. Hop-2 is a per-session key minted by
  the bastion and pushed to the device; the Linux agent keeps Hop-2 dormant behind
  systemd socket activation.
- Host keys are pinned (`SENTINEL_BASTION_KNOWN_HOSTS`). An empty pin falls back to
  trust-on-first-use; set it in production.
- Remote-assist sessions should be logged, time-bounded, and visible to the device user
  where the law requires it.

## Threat model

| Threat | Mitigation |
| :--- | :--- |
| Stolen operator password | TOTP/WebAuthn, rate limits, session revocation, audit logs |
| Stolen device | Device-owner lock/wipe, remote session revocation |
| Malicious network / DPI | TLS, REALITY transport, relay fallbacks, certificate/host-key pinning |
| Compromised object storage credentials | Scoped per-bucket tokens, rotation, least privilege |
| Leaked build secrets | No production values in the repo; build-time properties and env vars |
| Rogue enrollment | Enrollment tickets are single-account, quota-limited, and revocable |
| Supply-chain risk in third-party binaries | Pin versions; verify hashes; rebuild from source where possible |

## Non-goals

- Protecting a device whose operating system is already compromised (root, malicious
  system app, physical implant).
- Hiding the agent from the device user. The app appears in the launcher/settings and
  holds device-admin privileges; that is intentional.
- Providing a hardened multi-tenant SaaS. The server is designed for a single operator
  or a small trusted team. Review isolation before exposing it to untrusted tenants.
- Replacing legal, HR, or parental-consent processes.

## Operator responsibilities

1. Obtain and document consent or another lawful basis.
2. Publish a clear privacy notice describing what is collected and why.
3. Limit operator access to the minimum necessary; use separate admin accounts.
4. Set retention limits and delete data you no longer need.
5. Keep the server, bastion, and agents patched.
6. Rotate credentials and review audit logs.
7. Comply with local law, including wiretap, employee-monitoring, and child-protection
   rules.
