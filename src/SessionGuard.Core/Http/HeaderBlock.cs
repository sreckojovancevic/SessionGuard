using System.Buffers;

namespace SessionGuard.Core.Http;

/// <summary>
/// A mutable HTTP head (start line + header lines) held as raw bytes.
///
/// Every operation works on <see cref="Span{Byte}"/>. Nothing here converts a
/// header value to <see cref="string"/>, which is the point: a managed string
/// is immutable and GC-relocatable, so a session cookie that passes through one
/// cannot afterwards be wiped. Header names are compared with an ASCII
/// case-insensitive byte comparison instead.
///
/// Storage layout is the lines joined by CRLF, with no trailing terminator;
/// <see cref="WriteTo"/> appends the CRLFCRLF that ends a head on the wire.
/// </summary>
public sealed class HeaderBlock : IDisposable
{
    private byte[] _buf;
    private int _len;

    public HeaderBlock(ReadOnlySpan<byte> head)
    {
        _buf = ArrayPool<byte>.Shared.Rent(Math.Max(1024, head.Length * 2));
        head.CopyTo(_buf);
        _len = head.Length;
    }

    public int Length => _len;
    public ReadOnlySpan<byte> Span => _buf.AsSpan(0, _len);

    // ---------------------------------------------------------------- lines

    /// <summary>Range of the line at <paramref name="index"/>, or false past the end.</summary>
    public bool TryGetLine(int index, out int start, out int length)
    {
        start = 0;
        length = 0;
        int pos = 0, line = 0;
        while (pos <= _len)
        {
            int nl = IndexOfCrLf(_buf.AsSpan(pos, _len - pos));
            int end = nl < 0 ? _len : pos + nl;
            if (line == index)
            {
                start = pos;
                length = end - pos;
                return true;
            }
            if (nl < 0) return false;
            pos = end + 2;
            line++;
        }
        return false;
    }

    public ReadOnlySpan<byte> StartLine =>
        TryGetLine(0, out int s, out int l) ? _buf.AsSpan(s, l) : ReadOnlySpan<byte>.Empty;

    private static int IndexOfCrLf(ReadOnlySpan<byte> s)
    {
        for (int i = 0; i + 1 < s.Length; i++)
            if (s[i] == (byte)'\r' && s[i + 1] == (byte)'\n') return i;
        return -1;
    }

    // -------------------------------------------------------------- lookup

    /// <summary>
    /// Value range of the first header named <paramref name="name"/>.
    /// Only header lines are considered; the start line is skipped, and a match
    /// requires the name to be followed by ':' so that "Cookie" never matches
    /// inside "Set-Cookie" or inside a request body.
    /// </summary>
    public bool TryGetValue(ReadOnlySpan<byte> name, out int start, out int length)
    {
        for (int i = 1; TryGetLine(i, out int ls, out int ll); i++)
        {
            if (IsHeaderNamed(_buf.AsSpan(ls, ll), name, out int vOff))
            {
                start = ls + vOff;
                length = ll - vOff;
                return true;
            }
        }
        start = 0;
        length = 0;
        return false;
    }

    public bool Has(ReadOnlySpan<byte> name) => TryGetValue(name, out _, out _);

    private static bool IsHeaderNamed(ReadOnlySpan<byte> line, ReadOnlySpan<byte> name,
                                      out int valueOffset)
    {
        valueOffset = 0;
        if (line.Length < name.Length + 1) return false;
        for (int i = 0; i < name.Length; i++)
            if (ToLower(line[i]) != ToLower(name[i])) return false;

        int p = name.Length;
        while (p < line.Length && (line[p] == (byte)' ' || line[p] == (byte)'\t')) p++;
        if (p >= line.Length || line[p] != (byte)':') return false;
        p++;
        while (p < line.Length && (line[p] == (byte)' ' || line[p] == (byte)'\t')) p++;
        valueOffset = p;
        return true;
    }

    private static byte ToLower(byte b) => (byte)(b >= 'A' && b <= 'Z' ? b + 32 : b);

    // --------------------------------------------------------------- edits

    /// <summary>Removes every header line with this name. Returns how many went.</summary>
    public int RemoveAll(ReadOnlySpan<byte> name)
    {
        int removed = 0;
        int i = 1;
        while (TryGetLine(i, out int ls, out int ll))
        {
            if (IsHeaderNamed(_buf.AsSpan(ls, ll), name, out _))
            {
                // Take the CRLF that precedes this line with it.
                int cut = ll + 2;
                int from = ls + ll + 2 <= _len ? ls + ll + 2 : _len;
                int tail = _len - from;
                if (tail > 0) _buf.AsSpan(from, tail).CopyTo(_buf.AsSpan(ls));
                // Wipe the vacated bytes: they may have held a credential.
                _buf.AsSpan(_len - cut, cut).Clear();
                _len -= cut;
                removed++;
                continue; // same index now points at the next line
            }
            i++;
        }
        return removed;
    }

    /// <summary>Appends "name: value" as a new header line.</summary>
    public void Append(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        int need = 2 + name.Length + 2 + value.Length;
        EnsureCapacity(_len + need);
        var dst = _buf.AsSpan(_len);
        dst[0] = (byte)'\r';
        dst[1] = (byte)'\n';
        name.CopyTo(dst.Slice(2));
        dst[2 + name.Length] = (byte)':';
        dst[3 + name.Length] = (byte)' ';
        value.CopyTo(dst.Slice(4 + name.Length));
        _len += need;
    }

    /// <summary>Replaces the value of a header, appending it if absent.</summary>
    public void Set(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
    {
        RemoveAll(name);
        Append(name, value);
    }

    private void EnsureCapacity(int wanted)
    {
        if (wanted <= _buf.Length) return;
        var bigger = ArrayPool<byte>.Shared.Rent(Math.Max(wanted, _buf.Length * 2));
        _buf.AsSpan(0, _len).CopyTo(bigger);
        _buf.AsSpan(0, _len).Clear();
        ArrayPool<byte>.Shared.Return(_buf);
        _buf = bigger;
    }

    /// <summary>Writes head + CRLFCRLF into <paramref name="dst"/>.</summary>
    public int WriteTo(Span<byte> dst)
    {
        _buf.AsSpan(0, _len).CopyTo(dst);
        dst[_len] = (byte)'\r';
        dst[_len + 1] = (byte)'\n';
        dst[_len + 2] = (byte)'\r';
        dst[_len + 3] = (byte)'\n';
        return _len + 4;
    }

    public int WireLength => _len + 4;

    public void Dispose()
    {
        if (_buf.Length == 0) return;
        _buf.AsSpan(0, _len).Clear();
        ArrayPool<byte>.Shared.Return(_buf);
        _buf = Array.Empty<byte>();
        _len = 0;
    }
}
