# Security Policy

## Supported versions

Security fixes are applied to the `main` branch. There are no maintained release
branches yet; if you deploy a fork, track upstream and re-base regularly.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting ("Security" → "Report a vulnerability")
if it is enabled on the repository. Otherwise email the maintainers at the address
configured in this repository's `SECURITY` contact.

Please include:

- the affected component (`server`, `android-agent`, `android-client`, `windows-agent`,
  `linux-agent`) and version/commit;
- a description of the issue and its impact;
- reproduction steps or a proof of concept;
- any suggested remediation.

We aim to acknowledge reports within 72 hours and to publish an advisory once a fix is
available. Please give us a reasonable window before public disclosure.

## Scope

In scope:

- authentication, session, and authorization flaws in `server/`;
- cryptographic weaknesses in device-payload encryption or key handling;
- command injection, path traversal, SSRF, and deserialization issues;
- privilege escalation in the agents;
- leaks of secrets in logs, errors, or the web dashboard.

Out of scope:

- attacks that require a rooted device, physical access to the server, or an already
  compromised host;
- social engineering;
- denial of service through raw traffic volume;
- issues in third-party binaries (report those upstream).

## Deployment hardening checklist

- [ ] Set `ADMIN_PASS` to a unique, high-entropy value. There is no default.
- [ ] Set `SESSION_SECRET`, `ENC_PASSPHRASE`, and `HWID_KEY`.
- [ ] Serve the dashboard over HTTPS and set `SERVER_ORIGIN` to the public origin.
- [ ] Keep secrets in Docker secrets or a secret manager, never in `.env` files that
      are committed or backed up in plaintext.
- [ ] Restrict the server's inbound ports; expose only the reverse proxy.
- [ ] Rotate object-storage, Stripe, Tailscale, and SMTP credentials on a schedule.
- [ ] Enable audit logging and monitor for repeated login failures.
- [ ] Keep the host, Node.js, Go, .NET, and Android SDK toolchains patched.

## Sensitive capabilities

The Android agent requests powerful permissions (location, SMS, call logs, contacts,
camera, microphone, screen capture, app usage, device administration). The Windows and
Linux agents can execute commands and open support tunnels. Treat a deployment as a
high-value target and apply least privilege to the operator accounts.
