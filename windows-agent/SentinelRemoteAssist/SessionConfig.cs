namespace SentinelRemoteAssist;

/// <summary>
/// This build's session config. Two sources, mutually exclusive per build/run:
///   - Legacy ad hoc build: <see cref="SessionEmbedded"/>, baked in at build time by
///     new-support-session.sh (per-CUSTOMER Hop-1 key, no login).
///   - Account-linked build: <see cref="AccountLinkedSession"/>, populated at runtime by
///     AccountLoginForm (login) + RemoteAssistSocket (transport push) +
///     XrayTransportManager (local port) — a PER-DEVICE Hop-1 key (<see cref="Hop1Identity"/>,
///     generated on first run, sent up to the server on every "register") tunneled through xray
///     instead of a raw bastion port.
/// </summary>
internal sealed class SessionConfig
{
    public required string BastionHost { get; init; }
    public required int BastionPort { get; init; }
    public required int ForwardPort { get; init; }
    public required string KnownHostsLine { get; init; }
    public required string PrivateKeyPem { get; init; }

    public static bool IsConfigured => AccountLinkedSession.IsLinked
        ? Hop1Identity.IsConfigured
          && AccountLinkedSession.XrayLocalPort > 0 && AccountLinkedSession.BastionForwardPort > 0
        : SessionEmbedded.IsConfigured;

    public static SessionConfig Current => AccountLinkedSession.IsLinked
        ? new()
        {
            BastionHost = "127.0.0.1",
            BastionPort = AccountLinkedSession.XrayLocalPort,
            ForwardPort = AccountLinkedSession.BastionForwardPort,
            KnownHostsLine = Config.RemoteAssistBastionKnownHostsLine,
            PrivateKeyPem = Hop1Identity.PrivateKeyPem ?? "",
        }
        : new()
        {
            BastionHost = SessionEmbedded.BastionHost,
            BastionPort = SessionEmbedded.BastionPort,
            ForwardPort = SessionEmbedded.ForwardPort,
            KnownHostsLine = SessionEmbedded.KnownHostsLine,
            PrivateKeyPem = SessionEmbedded.PrivateKeyPem,
        };
}
