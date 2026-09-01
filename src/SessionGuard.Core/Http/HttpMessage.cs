using System.Buffers;

namespace SessionGuard.Core.Http;

/// <summary>One complete HTTP/1.1 message: an editable head plus its body bytes.</summary>
public sealed class HttpMessage : IDisposable
{
    private byte[] _body;
    private int _bodyLength;

    internal HttpMessage(HeaderBlock head, byte[] body, int bodyLength,
                         bool closeDelimited)
    {
        Head = head;
        _body = body;
        _bodyLength = bodyLength;
        CloseDelimited = closeDelimited;
    }

    public HeaderBlock Head { get; }
    public ReadOnlySpan<byte> Body => _body.AsSpan(0, _bodyLength);
    public int BodyLength => _bodyLength;

    /// <summary>True when the body was delimited by connection close, not by length.</summary>
    public bool CloseDelimited { get; }

    /// <summary>Status code for responses; 0 for requests.</summary>
    public int StatusCode
    {
        get
        {
            var sl = Head.StartLine;
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
    }

    public bool MethodIs(ReadOnlySpan<byte> method)
    {
        var sl = Head.StartLine;
        if (sl.Length < method.Length + 1) return false;
        for (int i = 0; i < method.Length; i++)
            if (sl[i] != method[i]) return false;
        return sl[method.Length] == (byte)' ';
    }

    /// <summary>
    /// Serializes head + body into a pooled buffer. The caller returns it.
    /// Any body that arrived chunked has already been decoded, so the head is
    /// normalized to Content-Length before this is called.
    /// </summary>
    public byte[] Serialize(out int length)
    {
        int total = Head.WireLength + _bodyLength;
        var buf = ArrayPool<byte>.Shared.Rent(total);
        int n = Head.WriteTo(buf);
        _body.AsSpan(0, _bodyLength).CopyTo(buf.AsSpan(n));
        length = total;
        return buf;
    }

    public void Dispose()
    {
        Head.Dispose();
        if (_body.Length > 0)
        {
            _body.AsSpan(0, _bodyLength).Clear();
            ArrayPool<byte>.Shared.Return(_body);
            _body = Array.Empty<byte>();
            _bodyLength = 0;
        }
    }
}
