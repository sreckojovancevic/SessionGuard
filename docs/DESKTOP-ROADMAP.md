# Notes toward refining the Windows client

Design conclusions reached in conversation, ordered by value against effort.
The point is that the reasoning survives — including the parts that argue
against doing something.

**Items 1 and 2 are implemented**: `HostProbe`, `InterceptionCache`, and the
reordering inside `ProxyEngine.InterceptAsync`, covered by four checks in the
end-to-end suite. Items 3 to 6 stand as written.

---

## 1. Probe a host when it is added

Cheap, and it removes the worst failure mode before the user ever meets it.

When the user types a host and presses Save, open one TLS connection to it
offering **only** `http/1.1` in ALPN. If that is refused, tell them straight
away:

```text
tiktok.com — HTTP/1.1 accepted
webcast.example.com — requires HTTP/2, cannot be protected yet
```

The same connection also reveals whether the name resolves, whether the host is
reachable, and whether its certificate chain validates normally — worth knowing,
because the proxy validates upstream and a broken chain would otherwise surface
later and look like a bug in SessionGuard.

**Word the result as an observation, not a promise.** "checked `tiktok.com`:
HTTP/1.1 accepted" is true. "this site will work" is not, because the probe
cannot see:

- **Subdomains.** With `*.tiktok.com` the probe hits `tiktok.com` while traffic
  goes to a dozen subdomains; any one of them may be HTTP/2 only.
- **Certificate pinning.** Pinning is enforced by the client, not the server, so
  a TLS handshake reveals nothing about it. This is the other main cause of
  breakage.
- **`localStorage`.** A host can speak HTTP/1.1 perfectly and keep no session in
  cookies at all.

## 2. Lossless fallback for hosts that turn out to be HTTP/2 only

The probe cannot catch a subdomain discovered mid-browse. That case has to be
handled at connection time — and the failure mode is worse than it looks.

**It would not be "protected but slower"; it would be broken.** Protection and
interception are the same act: once TLS has been terminated with the browser,
there is no way back to a tunnel on that connection. Either the upstream
handshake fails, or the origin speaks h2 and the HTTP/1.1 parser receives
`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` followed by binary frames.

The fix is a reordering, not new protocol support. Today:

```text
CONNECT arrives
→ 200 Connection Established
→ TLS handshake with the browser (our leaf)      <- committed here
→ TLS to upstream                                <- discover the problem here
```

Instead:

```text
CONNECT arrives
→ 200 Connection Established
→ TLS to upstream FIRST
   ├─ succeeded → TLS handshake with the browser, intercept as usual
   └─ failed    → close it, open plain TCP, relay from the first byte
```

The detail that makes this work: **do not read anything from the client until
upstream is settled.** Its ClientHello sits untouched in the socket buffer, so
falling back to a blind tunnel relays it as the first byte and the browser never
learns anything happened. Zero failed requests.

The cost is one discarded upstream connection per host, paid once because the
result is cached — per exact hostname, with a TTL of an hour or so, since a site
may fix its configuration and a failure may be transient.

**A skipped host must be visible.** Something like *"2 hosts skipped:
`webcast.tiktok.com` — requires HTTP/2"* in the UI. A silent skip is a silent
hole in the protection, and this project's whole claim is that the holes are
written down.

## 3. Vault on disk

Applicable directly; the key structure is worked out in
[`OPNSENSE-NOTES.md`](OPNSENSE-NOTES.md) and the same envelope applies here.
`Seal()` already returns a self-contained blob, so only serialisation of the map
is missing.

The motivation on the desktop is usability rather than necessity: today, closing
the application means signing in everywhere again, which is probably the main
reason someone would not run it daily.

But note what is given up. **A powered-off laptop currently holds nothing at
all.** With persistence it holds a sealed blob whose safety rests entirely on the
TPM binding — strong, but a different claim.

So: persistence should be opt-in and should **require a real presence mode, not
`None`**. Otherwise the credential survives a reboot with no human gesture
anywhere in the chain.

**One DEK for the whole file, not per cookie.** Each entry carrying its own
RSA-2048 wrap is wasteful and means N TPM operations per request. One wrap per
file, unsealed once per lease and held in memory until the lease closes, reduces
that to one — which also removes the per-cookie consent-prompt storm that makes
TPM-consent mode unusable today.

That is a deliberate trade and should be stated in the UI, not slipped in:
**per-use consent becomes per-lease consent.**

## 4. Suggesting hosts to protect

The user not knowing what to type is a real problem. Detecting it automatically
is not possible, and that is the design working correctly rather than a gap:
unprotected traffic is a blind tunnel, so `Set-Cookie` on a host that is not yet
protected is never visible. Seeing it requires intercepting it, and intercepting
it is exactly what "add to the list" means.

What is possible:

- **Frequency from CONNECT.** Hostnames are visible even for tunnelled traffic.
  Collect what the user visits repeatedly across sessions, filter obvious CDN and
  telemetry domains, and offer the rest as suggestions.
- **A curated preset list** with correct wildcard patterns for common sites.
  Cheapest thing on this page and immediately useful.
- **Confirmation after the fact.** Once a host is protected and cookies are
  captured, say so. And the inverse: if nothing is captured after a while,
  suggest removing it — that host probably keeps its session in `localStorage`.

**What not to do:** read the browser's own cookie database to find where sessions
exist. Technically possible, and precisely what an infostealer does. It would be
flagged by anti-virus and is not defensible in a security product.

## 5. HTTP/2 — the honest cost

Left last deliberately. This is not a weekend item and it carries an
architectural price worth understanding before starting.

HTTP/2 has no text headers. It has HPACK: binary, with a **dynamic table that is
per-connection state**. Finding the bytes `Cookie:` and rewriting them is not
possible. It needs the whole layer — frames, streams, an HPACK
encoder/decoder with its dynamic table, flow control, SETTINGS, GOAWAY. Plus a
detail waiting at the end: in HTTP/2 the `Cookie` header may be split across
several fields and must be joined with `; `.

.NET offers no API for this shape. Kestrel does h2 as a server, not as a
transparent intermediary that preserves streams. Two paths:

| Path | Gains | Costs |
|---|---|---|
| Write HPACK directly | keeps byte-level handling and the "no managed `string` copies of secrets" property | substantial work |
| YARP / Kestrel | the platform handles h2 on both sides | headers become `HttpRequestMessage` strings — **the property the project most insists on is lost** |

That is the real decision, not the amount of code.

And it is worth asking whether it is needed. Nothing is advertised to the
browser, so it falls back to HTTP/1.1 **for protected hosts only**; upstream now
asks for HTTP/1.1 explicitly, which is what makes an h2-only origin fail early
enough to tunnel instead. The cost is speed on a handful of sites, not breakage.
On an appliance HTTP/2 is mandatory; here it is an optimisation.

## 6. The clock that actually matters: HTTP/3

QUIC runs over UDP, and a system proxy does not intercept UDP at all.

What saves this design today is that Chrome disables QUIC when a proxy is
configured. That is a convention, not a guarantee, and it is the assumption most
likely to expire.
