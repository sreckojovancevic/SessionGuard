using System.Buffers;

namespace SessionGuard.Core.Http;

/// <summary>
/// Real HTTP/1.1 framing over a stream.
///
/// The previous versions of this proxy treated one ReadAsync as one message.
/// That works only for tiny replies: anything past the first read is either
/// truncated or misparsed as the next message. This reader instead accumulates
/// until the head terminator, then reads exactly the body the head describes —
/// by Content-Length, by chunked decoding, or (responses only) to end of stream.
/// </summary>
public static class HttpReader
{
    private static ReadOnlySpan<byte> ContentLength => "Content-Length"u8;
    private static ReadOnlySpan<byte> TransferEncoding => "Transfer-Encoding"u8;

    public const int MaxHeadBytes = 128 * 1024;
    public const int MaxBodyBytes = 64 * 1024 * 1024;

    /// <summary>
    /// Reads one message. <paramref name="isResponse"/> selects response rules
    /// (status-based bodiless replies, close-delimited bodies).
    /// <paramref name="headRequest"/> must be true for the response to a HEAD.
    /// Returns null at a clean end of stream.
    /// </summary>
    public static async Task<HttpMessage?> ReadAsync(
        Stream stream, bool isResponse, bool headRequest,
        CancellationToken token)
    {
        var (headBuf, headLen, overflow, overflowLen) =
            await ReadHeadAsync(stream, token).ConfigureAwait(false);
        if (headBuf is null) return null;

        HeaderBlock head;
        try
        {
            head = new HeaderBlock(headBuf.AsSpan(0, headLen));
        }
        finally
        {
            headBuf.AsSpan(0, headLen).Clear();
            ArrayPool<byte>.Shared.Return(headBuf);
        }

        try
        {
            int status = isResponse ? StatusOf(head) : 0;
            bool bodyless = isResponse &&
                            (headRequest || status == 204 || status == 304 ||
                             (status >= 100 && status < 200));

            if (bodyless)
            {
                Normalize(head, 0);
                ReturnOverflow(overflow, overflowLen);
                return new HttpMessage(head, Array.Empty<byte>(), 0, false);
            }

            bool chunked = IsChunked(head);
            long declared = ContentLengthOf(head);

            if (chunked)
            {
                var (body, len) = await ReadChunkedAsync(
                    stream, overflow, overflowLen, token).ConfigureAwait(false);
                head.RemoveAll(TransferEncoding);
                Normalize(head, len);
                return new HttpMessage(head, body, len, false);
            }

            if (declared >= 0)
            {
                var (body, len) = await ReadExactAsync(
                    stream, (int)declared, overflow, overflowLen, token)
                    .ConfigureAwait(false);
                Normalize(head, len);
                return new HttpMessage(head, body, len, false);
            }

            if (!isResponse)
            {
                // A request with neither header has no body.
                Normalize(head, 0);
                ReturnOverflow(overflow, overflowLen);
                return new HttpMessage(head, Array.Empty<byte>(), 0, false);
            }

            // Response with no length information: body runs to end of stream.
            var (rest, restLen) = await ReadToEndAsync(
                stream, overflow, overflowLen, token).ConfigureAwait(false);
            Normalize(head, restLen);
            return new HttpMessage(head, rest, restLen, true);
        }
        catch
        {
            head.Dispose();
            throw;
        }
    }

    private static void ReturnOverflow(byte[] overflow, int len)
    {
        if (overflow.Length == 0) return;
        overflow.AsSpan(0, len).Clear();
        ArrayPool<byte>.Shared.Return(overflow);
    }

    /// <summary>Rewrites the head so the body it describes is exactly what we hold.</summary>
    private static void Normalize(HeaderBlock head, int bodyLength)
    {
        head.RemoveAll(TransferEncoding);
        Span<byte> digits = stackalloc byte[20];
        int n = WriteInt(bodyLength, digits);
        head.Set(ContentLength, digits.Slice(0, n));
    }

    private static int WriteInt(int value, Span<byte> dst)
    {
        if (value == 0) { dst[0] = (byte)'0'; return 1; }
        Span<byte> tmp = stackalloc byte[20];
        int i = 0;
        while (value > 0) { tmp[i++] = (byte)('0' + value % 10); value /= 10; }
        for (int j = 0; j < i; j++) dst[j] = tmp[i - 1 - j];
        return i;
    }

    private static int StatusOf(HeaderBlock head)
    {
        var sl = head.StartLine;
        int sp = sl.IndexOf((byte)' ');
        if (sp < 0 || sp + 4 > sl.Length) return 0;
        int v = 0;
        for (int i = sp + 1; i < sp + 4; i++)
        {
            if (sl[i] < '0' || sl[i] > '9') return 0;
            v = v * 10 + (sl[i] - '0');
        }
        return v;
    }

    private static bool IsChunked(HeaderBlock head)
    {
        if (!head.TryGetValue(TransferEncoding, out int s, out int l)) return false;
        var v = head.Span.Slice(s, l);
        ReadOnlySpan<byte> want = "chunked"u8;
        for (int i = 0; i + want.Length <= v.Length; i++)
        {
            bool hit = true;
            for (int j = 0; j < want.Length; j++)
            {
                byte b = v[i + j];
                if (b >= 'A' && b <= 'Z') b += 32;
                if (b != want[j]) { hit = false; break; }
            }
            if (hit) return true;
        }
        return false;
    }

    private static long ContentLengthOf(HeaderBlock head)
    {
        if (!head.TryGetValue(ContentLength, out int s, out int l)) return -1;
        var v = head.Span.Slice(s, l);
        long acc = 0;
        bool any = false;
        foreach (byte b in v)
        {
            if (b == ' ' || b == '\t') continue;
            if (b < '0' || b > '9') return any ? acc : -1;
            acc = acc * 10 + (b - '0');
            any = true;
            if (acc > MaxBodyBytes) return MaxBodyBytes;
        }
        return any ? acc : -1;
    }

    // ------------------------------------------------------------------ io

    /// <summary>
    /// Reads until CRLFCRLF. Returns the head plus whatever body bytes arrived
    /// in the same reads, so nothing that was already pulled off the socket is
    /// lost — the bug that made the earlier StreamReader version unusable.
    /// </summary>
    private static async Task<(byte[]? head, int headLen, byte[] rest, int restLen)>
        ReadHeadAsync(Stream stream, CancellationToken token)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(16 * 1024);
        int have = 0, scanned = 0;
        try
        {
            while (true)
            {
                if (have == buf.Length)
                {
                    if (have >= MaxHeadBytes) throw new InvalidDataException("head too large");
                    var bigger = ArrayPool<byte>.Shared.Rent(buf.Length * 2);
                    buf.AsSpan(0, have).CopyTo(bigger);
                    buf.AsSpan(0, have).Clear();
                    ArrayPool<byte>.Shared.Return(buf);
                    buf = bigger;
                }

                int n = await stream.ReadAsync(buf.AsMemory(have), token)
                                    .ConfigureAwait(false);
                if (n == 0)
                {
                    ArrayPool<byte>.Shared.Return(buf);
                    return (null, 0, Array.Empty<byte>(), 0);
                }
                have += n;

                int idx = IndexOfTerminator(buf.AsSpan(0, have), ref scanned);
                if (idx >= 0)
                {
                    int restLen = have - (idx + 4);
                    byte[] rest = Array.Empty<byte>();
                    if (restLen > 0)
                    {
                        rest = ArrayPool<byte>.Shared.Rent(restLen);
                        buf.AsSpan(idx + 4, restLen).CopyTo(rest);
                    }
                    return (buf, idx, rest, restLen);
                }
            }
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(buf);
            throw;
        }
    }

    private static int IndexOfTerminator(ReadOnlySpan<byte> s, ref int scanned)
    {
        int start = Math.Max(0, scanned - 3);
        for (int i = start; i + 3 < s.Length; i++)
            if (s[i] == '\r' && s[i + 1] == '\n' && s[i + 2] == '\r' && s[i + 3] == '\n')
            {
                scanned = s.Length;
                return i;
            }
        scanned = s.Length;
        return -1;
    }

    private static async Task<(byte[], int)> ReadExactAsync(
        Stream stream, int count, byte[] prefix, int prefixLen,
        CancellationToken token)
    {
        if (count > MaxBodyBytes) throw new InvalidDataException("body too large");
        byte[] body = ArrayPool<byte>.Shared.Rent(Math.Max(1, count));
        int have = Math.Min(prefixLen, count);
        if (have > 0) prefix.AsSpan(0, have).CopyTo(body);
        ReturnOverflow(prefix, prefixLen);

        while (have < count)
        {
            int n = await stream.ReadAsync(body.AsMemory(have, count - have), token)
                                .ConfigureAwait(false);
            if (n == 0) break;
            have += n;
        }
        return (body, have);
    }

    private static async Task<(byte[], int)> ReadToEndAsync(
        Stream stream, byte[] prefix, int prefixLen, CancellationToken token)
    {
        byte[] body = ArrayPool<byte>.Shared.Rent(Math.Max(8192, prefixLen * 2));
        int have = prefixLen;
        if (prefixLen > 0) prefix.AsSpan(0, prefixLen).CopyTo(body);
        ReturnOverflow(prefix, prefixLen);

        while (true)
        {
            if (have == body.Length)
            {
                var bigger = ArrayPool<byte>.Shared.Rent(body.Length * 2);
                body.AsSpan(0, have).CopyTo(bigger);
                body.AsSpan(0, have).Clear();
                ArrayPool<byte>.Shared.Return(body);
                body = bigger;
            }
            int n = await stream.ReadAsync(body.AsMemory(have), token)
                                .ConfigureAwait(false);
            if (n == 0) return (body, have);
            have += n;
            if (have > MaxBodyBytes) throw new InvalidDataException("body too large");
        }
    }

    /// <summary>Decodes a chunked body into a flat buffer.</summary>
    private static async Task<(byte[], int)> ReadChunkedAsync(
        Stream stream, byte[] prefix, int prefixLen, CancellationToken token)
    {
        var src = new BufferedSource(stream, prefix, prefixLen);
        byte[] body = ArrayPool<byte>.Shared.Rent(8192);
        int have = 0;
        try
        {
            while (true)
            {
                int size = await src.ReadChunkSizeAsync(token).ConfigureAwait(false);
                if (size == 0)
                {
                    // Trailer section, then the final CRLF.
                    while (true)
                    {
                        int len = await src.ReadLineAsync(token).ConfigureAwait(false);
                        if (len <= 0) break;
                    }
                    return (body, have);
                }
                if (have + size > MaxBodyBytes) throw new InvalidDataException("body too large");
                while (have + size > body.Length)
                {
                    var bigger = ArrayPool<byte>.Shared.Rent(body.Length * 2);
                    body.AsSpan(0, have).CopyTo(bigger);
                    body.AsSpan(0, have).Clear();
                    ArrayPool<byte>.Shared.Return(body);
                    body = bigger;
                }
                await src.ReadExactAsync(body.AsMemory(have, size), token)
                         .ConfigureAwait(false);
                have += size;
                await src.ExpectCrLfAsync(token).ConfigureAwait(false);
            }
        }
        finally
        {
            src.Dispose();
        }
    }

    /// <summary>Small pushback reader so chunk framing can read byte by byte cheaply.</summary>
    private sealed class BufferedSource : IDisposable
    {
        private readonly Stream _stream;
        private byte[] _buf;
        private int _pos, _len;

        public BufferedSource(Stream stream, byte[] prefix, int prefixLen)
        {
            _stream = stream;
            _buf = ArrayPool<byte>.Shared.Rent(Math.Max(8192, prefixLen));
            if (prefixLen > 0)
            {
                prefix.AsSpan(0, prefixLen).CopyTo(_buf);
                _len = prefixLen;
                prefix.AsSpan(0, prefixLen).Clear();
                ArrayPool<byte>.Shared.Return(prefix);
            }
        }

        private async ValueTask<bool> FillAsync(CancellationToken token)
        {
            if (_pos < _len) return true;
            _pos = 0;
            _len = await _stream.ReadAsync(_buf.AsMemory(), token).ConfigureAwait(false);
            return _len > 0;
        }

        public async ValueTask<int> ReadByteAsync(CancellationToken token)
        {
            if (!await FillAsync(token).ConfigureAwait(false)) return -1;
            return _buf[_pos++];
        }

        public async ValueTask<int> ReadChunkSizeAsync(CancellationToken token)
        {
            int size = 0, digits = 0;
            while (true)
            {
                int b = await ReadByteAsync(token).ConfigureAwait(false);
                if (b < 0) throw new InvalidDataException("truncated chunk size");
                if (b == '\r')
                {
                    int nl = await ReadByteAsync(token).ConfigureAwait(false);
                    if (nl != '\n') throw new InvalidDataException("bad chunk terminator");
                    if (digits == 0) throw new InvalidDataException("empty chunk size");
                    return size;
                }
                if (b == ';')
                {
                    // chunk extension: skip to CRLF
                    while (true)
                    {
                        int c = await ReadByteAsync(token).ConfigureAwait(false);
                        if (c < 0) throw new InvalidDataException("truncated extension");
                        if (c == '\r')
                        {
                            int nl2 = await ReadByteAsync(token).ConfigureAwait(false);
                            if (nl2 != '\n') throw new InvalidDataException("bad chunk terminator");
                            return size;
                        }
                    }
                }
                int v = HexVal(b);
                if (v < 0) throw new InvalidDataException("bad chunk size digit");
                size = size * 16 + v;
                digits++;
                if (size > MaxBodyBytes) throw new InvalidDataException("chunk too large");
            }
        }

        private static int HexVal(int b) =>
            b >= '0' && b <= '9' ? b - '0' :
            b >= 'a' && b <= 'f' ? b - 'a' + 10 :
            b >= 'A' && b <= 'F' ? b - 'A' + 10 : -1;

        public async ValueTask<int> ReadLineAsync(CancellationToken token)
        {
            int n = 0;
            while (true)
            {
                int b = await ReadByteAsync(token).ConfigureAwait(false);
                if (b < 0) return n;
                if (b == '\r')
                {
                    int nl = await ReadByteAsync(token).ConfigureAwait(false);
                    if (nl != '\n') throw new InvalidDataException("bad line terminator");
                    return n;
                }
                n++;
            }
        }

        public async ValueTask ReadExactAsync(Memory<byte> dst, CancellationToken token)
        {
            int off = 0;
            while (off < dst.Length)
            {
                if (_pos < _len)
                {
                    int take = Math.Min(_len - _pos, dst.Length - off);
                    _buf.AsSpan(_pos, take).CopyTo(dst.Span.Slice(off));
                    _pos += take;
                    off += take;
                    continue;
                }
                int n = await _stream.ReadAsync(dst.Slice(off), token).ConfigureAwait(false);
                if (n == 0) throw new InvalidDataException("truncated chunk body");
                off += n;
            }
        }

        public async ValueTask ExpectCrLfAsync(CancellationToken token)
        {
            int a = await ReadByteAsync(token).ConfigureAwait(false);
            int b = await ReadByteAsync(token).ConfigureAwait(false);
            if (a != '\r' || b != '\n') throw new InvalidDataException("bad chunk trailer");
        }

        public void Dispose()
        {
            if (_buf.Length == 0) return;
            _buf.AsSpan().Clear();
            ArrayPool<byte>.Shared.Return(_buf);
            _buf = Array.Empty<byte>();
        }
    }
}
