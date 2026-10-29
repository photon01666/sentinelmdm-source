using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// HTTP client port of the Android agent's AccountLinkActivity.kt login flow:
///   POST /api/auth/prelogin -> PBKDF2-SHA256 prehash -> POST /login or /api/device-admin/login
///   (build-variant-selected, see Config.AdminAgent) -> optional TOTP step ->
///   POST /api/enrollment/ticket (session-cookie authed) -> single-use ticket, consumed by
///   RemoteAssistSocket's next handshake.
///
/// "prehash-v1": base64(PBKDF2-SHA256(password, utf8("sentinel-auth-v1|")+authSaltBytes, 600_000,
/// 32)) — see docs/ARCHITECTURE.md's client-side password pre-hashing invariant. The plaintext only ever rides
/// when the account hasn't migrated to the scheme yet (server returns migrate:true) or the server
/// predates /api/auth/prelogin, both handled below exactly like the Kotlin original.
/// </summary>
internal sealed class AccountAuthClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly CookieContainer _cookies = new();

    public AccountAuthClient()
    {
        var handler = new HttpClientHandler { CookieContainer = _cookies, UseCookies = true };
        _http = new HttpClient(handler) { BaseAddress = new Uri(Config.WebUrl) };
    }

    public sealed record LoginResult(bool Ok, bool TotpRequired, string? Error);

    /// <summary>identifier is an email (public build) or a username/email (admin build) — the
    /// server itself detects "@" to decide how to look the account up, same as the Kotlin client.</summary>
    public async Task<LoginResult> LoginAsync(string identifier, string password, CancellationToken ct = default)
    {
        string authHashOrNull = null!;
        var salt = "";
        var iterations = 600_000;
        var migrate = false;
        var scheme = "";
        try
        {
            var preResp = await _http.PostAsJsonAsync("/api/auth/prelogin", new { identifier }, ct);
            if (preResp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(await preResp.Content.ReadAsStringAsync(ct));
                var root = doc.RootElement;
                if (root.TryGetProperty("auth_salt", out var s)) salt = s.GetString() ?? "";
                if (root.TryGetProperty("scheme", out var sc)) scheme = sc.GetString() ?? "";
                if (root.TryGetProperty("iterations", out var it) && it.TryGetInt32(out var itv)) iterations = itv;
                if (root.TryGetProperty("migrate", out var m)) migrate = m.GetBoolean();
            }
        }
        catch
        {
            // Connection failure at prelogin — fall through and let the actual login POST below
            // surface the real error (mirrors the Kotlin client's onFailure -> "Connection failed").
        }

        object body;
        if (scheme == "prehash-v1" && !string.IsNullOrEmpty(salt) && !migrate)
        {
            authHashOrNull = ComputeAuthPrehash(password, salt, iterations);
            body = new { username = identifier, authHash = authHashOrNull };
        }
        else
        {
            body = new { username = identifier, password };
        }

        var loginPath = Config.AdminAgent ? "/api/device-admin/login" : "/login";
        HttpResponseMessage resp;
        try
        {
            resp = await _http.PostAsJsonAsync(loginPath, body, ct);
        }
        catch (Exception ex)
        {
            return new LoginResult(false, false, $"Connection failed — check your network ({ex.Message})");
        }

        var respText = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
        {
            var msg = TryGetError(respText) ?? "Invalid credentials";
            return new LoginResult(false, false, msg);
        }

        using var okDoc = JsonDocument.Parse(string.IsNullOrEmpty(respText) ? "{}" : respText);
        var totpRequired = okDoc.RootElement.TryGetProperty("totp_required", out var tr) && tr.GetBoolean();
        return new LoginResult(true, totpRequired, null);
    }

    public async Task<LoginResult> VerifyTotpAsync(string code, CancellationToken ct = default)
    {
        var path = Config.AdminAgent ? "/api/device-admin/login/totp" : "/login/totp";
        HttpResponseMessage resp;
        try
        {
            resp = await _http.PostAsJsonAsync(path, new { code }, ct);
        }
        catch (Exception ex)
        {
            return new LoginResult(false, false, $"Connection failed — check your network ({ex.Message})");
        }
        var respText = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            return new LoginResult(false, false, TryGetError(respText) ?? "Invalid code");
        return new LoginResult(true, false, null);
    }

    public sealed record TicketResult(bool Ok, string? Ticket, string? Error);

    /// <summary>Requests a single-use enrollment ticket for THIS device (the session cookie from
    /// LoginAsync/VerifyTotpAsync authorizes it) — consumed by RemoteAssistSocket's next
    /// handshake, exactly mirroring the Kotlin client's requestTicket()/consumeEnrollmentTicket()
    /// server-side flow. This is the ONLY path that creates a device<->account binding.</summary>
    public async Task<TicketResult> RequestEnrollmentTicketAsync(string deviceId, CancellationToken ct = default)
    {
        HttpResponseMessage resp;
        try
        {
            resp = await _http.PostAsJsonAsync("/api/enrollment/ticket", new { deviceId }, ct);
        }
        catch (Exception ex)
        {
            return new TicketResult(false, null, $"Connection failed — check your network ({ex.Message})");
        }
        var respText = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            return new TicketResult(false, null, TryGetError(respText) ?? "Registration failed");
        using var doc = JsonDocument.Parse(string.IsNullOrEmpty(respText) ? "{}" : respText);
        var ticket = doc.RootElement.TryGetProperty("ticket", out var t) ? t.GetString() : null;
        if (string.IsNullOrEmpty(ticket))
            return new TicketResult(false, null, "Server returned no ticket — contact support");
        return new TicketResult(true, ticket, null);
    }

    private static string? TryGetError(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrEmpty(json) ? "{}" : json);
            return doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
        }
        catch { return null; }
    }

    /// <summary>base64(PBKDF2-SHA256(password, utf8("sentinel-auth-v1|")+authSaltBytes, iterations,
    /// 32 bytes)) — must byte-for-byte match the Kotlin client's computeAuthPrehash() and the
    /// server's verifyUserPassword(), see docs/ARCHITECTURE.md's auth-password-prehash invariant.</summary>
    private static string ComputeAuthPrehash(string password, string authSaltB64, int iterations)
    {
        var prefix = Encoding.UTF8.GetBytes("sentinel-auth-v1|");
        var saltBytes = Convert.FromBase64String(authSaltB64);
        var salt = new byte[prefix.Length + saltBytes.Length];
        Buffer.BlockCopy(prefix, 0, salt, 0, prefix.Length);
        Buffer.BlockCopy(saltBytes, 0, salt, prefix.Length, saltBytes.Length);
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return Convert.ToBase64String(pbkdf2.GetBytes(32));
    }

    public void Dispose() => _http.Dispose();
}
