# Open issues

Two things were left unresolved on the Windows client. Both are recorded with
the evidence, because in both cases the obvious reading turned out to be wrong
once already.

---

## 1. The system proxy is not honoured until it is set by hand

**Symptom.** With the Guard on, nothing is intercepted. Entering
`127.0.0.1:28080` manually in *Internet Options → Connections → LAN settings*
makes traffic flow through the proxy immediately, and everything then works.

**What is already ruled out.** The application can write to the registry — an
earlier run's `ProxyEnable=0` was found there, which only this code writes. The
`Restore()`-on-close defect that produced it is fixed: the marker file is now
the record of ownership, and with no marker `Restore()` changes nothing.

**What the next run should answer.** `TurnOn` now logs before each step:

```text
turn on: checking the root certificate
turn on: opening the listener on 127.0.0.1:28080
turn on: writing the system proxy setting
registry now says: system proxy ON -> 127.0.0.1:28080
```

The step the trace stops at is the answer. Three cases, distinguishable only
this way:

- stops before *writing* — something earlier threw; the registry was never
  touched, and "cannot write the proxy setting" was never the problem.
- reaches *writing* but `registry now says: system proxy OFF` — the write is
  going somewhere else. `Apply()` raises an exception naming the Windows account
  it is running as; a mismatch with the browser's account explains it, since
  each account has its own `HKCU`.
- registry says `ON` and the browser still ignores it — then WinINET is set
  correctly and the browser is the one not following it. Note the test browser
  is **Firefox Nightly**, which does follow the system proxy by default but
  keeps its own certificate store, so the root CA has to be imported there
  separately.

---

## 2. TikTok sign-in still ends in "Maximum number of attempts reached"

**What the `HttpOnly` rule fixed.** `msToken` is now correctly left with the
browser on every subdomain that sets it:

```text
left with the browser (script-readable, not HttpOnly):
  login-no1a.www.tiktok.com:msToken, mssdk-sg.tiktok.com:msToken,
  us.tiktok.com:msToken, web-sg.tiktok.com:msToken, www.tiktok.com:msToken
```

**What is still wrong.** The vault holds `tt_chain_token`, `ttwid`, `odin_tt`
and nothing else. Those are `HttpOnly`, so the rule takes them — but they are
not session credentials. They are device and anti-fraud tokens. No `sessionid`,
`sessionid_ss` or `sid_guard` ever appears, which means the sign-in never
completes.

**The hypothesis to test next.** `HttpOnly` answers *"can taking this cookie
break the page's script?"* It does not answer *"is this cookie a session
credential?"*, and those are different questions. A device token is invisible to
script yet still load-bearing for the server's risk engine: it is bound to the
browser and expected on **every** request, including the unauthenticated ones
during sign-in. But a vaulted cookie is injected only while a lease is open and
the calling process is authorized — so during a login flow, those tokens are
very likely going out missing. A device the risk engine has never seen before,
attempting authentication, is exactly what it is built to challenge.

If that is right, the rate limit is not a leftover from earlier testing; it is
being re-earned on each attempt.

**Cheapest experiment, before writing any code.** Turn the Guard **off**, sign
in, then turn it **on**. If browsing is then stable, the login flow specifically
is what breaks, and the fix is about *when* cookies are withheld rather than
*which*.

**If that confirms it**, two candidate designs, in order of how much they give
up:

1. **Guard only what a session credential looks like.** A name allowlist per
   host, defaulting to observed patterns (`sessionid*`, `sid_*`, `session*`,
   `auth*`), with device tokens passing through. Narrow and effective, but it is
   pattern-matching on names, which is guesswork dressed as policy — and it is
   the kind of rule that quietly stops matching when a site renames something.

2. **Withhold nothing until a session exists.** Capture a cookie into the vault
   but keep serving it to the browser until the host has issued something that
   looks like an authenticated session; only then start stripping. This keeps
   the whole sign-in flow byte-identical to an unguarded browser and only
   engages once there is a credential worth protecting. More faithful, more
   state to get right, and it means a window in which the cookie is in the
   browser profile — which must be stated, not glossed.

Also worth remembering independently of all this: **the rate limit is enforced
by the site and persists on its own clock.** Fixing the cause does not clear it.
A test run immediately after a failure proves nothing either way.
