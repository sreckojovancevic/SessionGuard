namespace SessionGuard.Core.Http;

/// <summary>
/// Cookie parsing at byte level.
///
/// The mistake worth naming: a Set-Cookie header is "name=value" followed by
/// attributes — "sessionid=abc; Path=/; HttpOnly; Secure". Storing the whole
/// header value and replaying it as a request cookie produces
/// "Cookie: session=sessionid=abc; Path=/; HttpOnly" and never authenticates.
/// Only the first name=value pair before the first ';' is the credential.
/// </summary>
public static class CookieBytes
{
    /// <summary>Splits a Set-Cookie value into its name and value ranges.</summary>
    public static bool TryParseSetCookie(ReadOnlySpan<byte> header,
                                         out Range name, out Range value)
    {
        name = default;
        value = default;

        int end = header.IndexOf((byte)';');
        var pair = end < 0 ? header : header.Slice(0, end);

        int eq = pair.IndexOf((byte)'=');
        if (eq <= 0) return false;

        int ns = 0, ne = eq;
        while (ns < ne && IsSpace(pair[ns])) ns++;
        while (ne > ns && IsSpace(pair[ne - 1])) ne--;
        if (ns == ne) return false;

        int vs = eq + 1, ve = pair.Length;
        while (vs < ve && IsSpace(pair[vs])) vs++;
        while (ve > vs && IsSpace(pair[ve - 1])) ve--;

        name = new Range(ns, ne);
        value = new Range(vs, ve);
        return true;
    }

    /// <summary>
    /// Attributes of a Set-Cookie, as far as the vault needs them.
    /// Attribute names and Path are not secrets, so they may become strings;
    /// the cookie value never does.
    /// </summary>
    public readonly record struct SetCookieAttributes(
        bool IsDeletion, string? Path, string? Domain);

    /// <summary>
    /// Reads the attributes after the first name=value pair.
    ///
    /// Deletion matters: a server logs you out by sending the cookie back with
    /// Max-Age=0 or a past Expires. Treating that as "the new value is empty"
    /// leaves a dead credential in the vault and keeps replaying it, so the
    /// user can never actually sign out.
    /// </summary>
    public static SetCookieAttributes ParseAttributes(ReadOnlySpan<byte> header)
    {
        bool deletion = false;
        string? path = null;
        string? domain = null;

        int semi = header.IndexOf((byte)';');
        if (semi < 0) return new SetCookieAttributes(false, null, null);

        int pos = semi + 1;
        while (pos <= header.Length)
        {
            int next = pos < header.Length ? header.Slice(pos).IndexOf((byte)';') : -1;
            int end = next < 0 ? header.Length : pos + next;
            var attr = header.Slice(pos, end - pos);

            int eq = attr.IndexOf((byte)'=');
            var key = Trim(eq < 0 ? attr : attr.Slice(0, eq));
            var val = Trim(eq < 0 ? ReadOnlySpan<byte>.Empty : attr.Slice(eq + 1));

            if (EqualsAsciiIgnoreCase(key, "max-age"u8))
            {
                if (TryParseLong(val, out long seconds) && seconds <= 0) deletion = true;
            }
            else if (EqualsAsciiIgnoreCase(key, "expires"u8))
            {
                // A date is not a secret, so parsing it through a string is fine.
                if (DateTimeOffset.TryParse(System.Text.Encoding.ASCII.GetString(val),
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal, out var when)
                    && when <= DateTimeOffset.UtcNow)
                    deletion = true;
            }
            else if (EqualsAsciiIgnoreCase(key, "path"u8) && !val.IsEmpty)
            {
                path = System.Text.Encoding.ASCII.GetString(val);
            }
            else if (EqualsAsciiIgnoreCase(key, "domain"u8) && !val.IsEmpty)
            {
                // Not a secret; the scope decision needs it as text.
                domain = System.Text.Encoding.ASCII.GetString(val);
            }

            if (next < 0) break;
            pos = end + 1;
        }

        return new SetCookieAttributes(deletion, path, domain);
    }

    private static ReadOnlySpan<byte> Trim(ReadOnlySpan<byte> s)
    {
        int a = 0, b = s.Length;
        while (a < b && IsSpace(s[a])) a++;
        while (b > a && IsSpace(s[b - 1])) b--;
        return s.Slice(a, b - a);
    }

    private static bool TryParseLong(ReadOnlySpan<byte> s, out long value)
    {
        value = 0;
        if (s.IsEmpty) return false;
        bool neg = s[0] == (byte)'-';
        int i = neg || s[0] == (byte)'+' ? 1 : 0;
        if (i >= s.Length) return false;
        for (; i < s.Length; i++)
        {
            if (s[i] < '0' || s[i] > '9') return false;
            value = value * 10 + (s[i] - '0');
        }
        if (neg) value = -value;
        return true;
    }

    /// <summary>
    /// RFC 6265 path-match. Without it the vault would attach a cookie scoped
    /// to /admin on every request to the host.
    /// </summary>
    public static bool PathMatches(string? cookiePath, string requestPath)
    {
        if (string.IsNullOrEmpty(cookiePath) || cookiePath == "/") return true;
        if (requestPath.Length == 0) requestPath = "/";
        if (!requestPath.StartsWith(cookiePath, StringComparison.Ordinal)) return false;
        return requestPath.Length == cookiePath.Length ||
               cookiePath.EndsWith("/", StringComparison.Ordinal) ||
               requestPath[cookiePath.Length] == '/';
    }

    /// <summary>
    /// Walks a request Cookie header, invoking <paramref name="onPair"/> for each
    /// name=value it contains. Used to keep unprotected cookies while dropping
    /// the guarded ones.
    /// </summary>
    public static void ForEachRequestCookie(ReadOnlySpan<byte> header,
                                            SpanPairAction onPair)
    {
        int pos = 0;
        while (pos < header.Length)
        {
            int semi = header.Slice(pos).IndexOf((byte)';');
            int end = semi < 0 ? header.Length : pos + semi;
            var pair = header.Slice(pos, end - pos);

            int eq = pair.IndexOf((byte)'=');
            if (eq > 0)
            {
                int ns = 0, ne = eq;
                while (ns < ne && IsSpace(pair[ns])) ns++;
                while (ne > ns && IsSpace(pair[ne - 1])) ne--;

                int vs = eq + 1, ve = pair.Length;
                while (vs < ve && IsSpace(pair[vs])) vs++;
                while (ve > vs && IsSpace(pair[ve - 1])) ve--;

                if (ns < ne) onPair(pair.Slice(ns, ne - ns), pair.Slice(vs, ve - vs));
            }

            if (semi < 0) break;
            pos = end + 1;
        }
    }

    public delegate void SpanPairAction(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value);

    private static bool IsSpace(byte b) => b == (byte)' ' || b == (byte)'\t';

    /// <summary>ASCII case-insensitive comparison, for cookie and header names.</summary>
    public static bool EqualsAsciiIgnoreCase(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            byte x = a[i], y = b[i];
            if (x >= 'A' && x <= 'Z') x += 32;
            if (y >= 'A' && y <= 'Z') y += 32;
            if (x != y) return false;
        }
        return true;
    }
}
