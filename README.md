# SessionGuard

SessionGuard is an experimental Windows client-side session-containment proxy.
It keeps protected HTTP session cookies out of the browser cookie jar and holds
them in a local vault protected by a TPM-backed key. A protected cookie is
attached to an outbound request only when the local authorization policy allows
it.

## Why this exists

SessionGuard started from a real incident: a session from my TikTok account was
stolen and subsequently used by someone else to access the account and run
their own LIVE.

The problem was not that the password was known. The problem was that the
session itself had become the credential. Once the session cookie was outside
the original browser environment, the service had no reason to distinguish the
attacker from the legitimate session.

That led to a simple question:

> What if the browser never had the protected session credential in the first
> place?

SessionGuard is an experiment around that question. Instead of allowing the
browser to persist the protected session cookie as ordinary browser state, the
cookie is kept in a local vault and supplied only when an authorized request
needs it.

The design is intentionally local: the service being accessed does not need to
implement a new session protocol.

> **Status: experimental prototype.** The proxy path, HTTP/1.1 handling,
> cookie/vault logic, process authorization and Windows TPM path are implemented
> and tested. Windows Hello presence is an optional policy, but its current
> implementation is still under development. Do not treat this project as a
> formally audited security product.

## What it does

```text
Browser
   |
   | Windows system proxy
   v
127.0.0.1:28080
   |
   v
SessionGuard
   |
   +-- protected hosts -> TLS interception -> cookie/vault policy
   |
   +-- other hosts -> untouched CONNECT tunnel
   |
   v
Internet
```

For protected hosts, the session cookie is captured from `Set-Cookie` and kept
in the vault instead of being left in the browser's cookie jar. On an authorized
request SessionGuard reconstructs the `Cookie` header immediately before the
request is sent upstream.

**Only `HttpOnly` cookies are captured.** A cookie without that attribute is one
the page's own JavaScript reads, so taking it breaks the site — and protects
nothing, since any script that could steal it can already read it from
`document.cookie`. Cookies left behind are named in the Vault panel.

The current Windows implementation uses:

- .NET 8 + WPF
- Windows system/WinINET proxy settings
- TPM-backed CNG key (`Microsoft Platform Crypto Provider`)
- DPAPI-protected local CA private key
- process identity based on PID, start time and process lineage
- optional Windows Hello / TPM consent presence policies
- HTTP/1.1 CONNECT and TLS interception

## Repository layout

```text
SessionGuard.sln
├─ src/SessionGuard.Core
│  └─ net8.0
│     ├─ HTTP framing and byte-level header handling
│     ├─ Cookie parsing and scope handling
│     ├─ TPM-independent session vault interface
│     ├─ lease/process authorization
│     ├─ local CA and TLS interception
│     └─ proxy engine
├─ src/SessionGuard.Windows
│  └─ net8.0-windows10.0.19041.0
│     ├─ WPF UI
│     ├─ TPM/CNG sealing
│     ├─ DPAPI CA store
│     ├─ Windows proxy switching
│     ├─ browser/process discovery
│     └─ Windows presence integration
└─ tests/SessionGuard.E2E
   └─ end-to-end proof of the Core behaviour
```

## Requirements

- Windows 10/11
- .NET 8 SDK for building
- TPM-backed Windows key storage for protected mode
- Administrator rights are **not** required by the application manifest; the
  current implementation operates in the user's HKCU profile, certificate
  store and `%LOCALAPPDATA%`.
- Internet access to restore NuGet packages when building from source

The application deliberately fails closed when the TPM-backed vault cannot be
opened. An explicit development switch is available for testing only:

```powershell
dotnet run --project .\src\SessionGuard.Windows -c Release -- --allow-insecure-dev-mode
```

That mode uses an in-memory sealer and is **not a security boundary**.

## Build

```powershell
dotnet build .\SessionGuard.sln -c Release
```

Run directly from the build output:

```powershell
dotnet run --project .\src\SessionGuard.Windows -c Release
```

Or create a self-contained Windows x64 publish directory:

```powershell
dotnet publish .\src\SessionGuard.Windows `
  -c Release `
  -r win-x64 `
  --self-contained true
```

For Windows ARM64 use `win-arm64` instead of `win-x64`.

## Quick start

1. Start SessionGuard.
2. Add the hostname(s) you want to protect in **Protected hosts**.
3. Press **Save**.
4. Press **Turn on**.
5. On first use, approve installation of the SessionGuard local root CA into
   the current user's trusted roots.
6. Start or refresh the browser.
7. Press **Refresh** in SessionGuard and select the browser process.
8. Choose the desired **Presence** policy.
9. Press **Unlock**.
10. Log in to the protected site.

For detailed operation, troubleshooting and the security model see
[`MANUAL.md`](MANUAL.md).

## Protected hosts

The list is stored at:

```text
%LOCALAPPDATA%\SessionGuard\protected-hosts.txt
```

Only hosts in this list are intercepted. Everything else is passed through as
an ordinary TLS tunnel.

Examples:

```text
example.com
www.example.com
*.tiktok.com
```

A plain hostname is exact. A leading `*.` covers the bare domain and its
subdomains.

You can also paste common URL forms into the UI; SessionGuard normalizes them
to a hostname.

## What the settings actually control

Three independent layers, easy to conflate:

| Layer | Active when | Governs |
|---|---|---|
| **Vault + non-exportability** | Guard on and host in the list | `Set-Cookie` is sealed with the TPM key and kept out of the browser profile |
| **Lease** | after **Unlock** | whether a stored cookie is put back into requests — for the selected browser process **and its descendants**, for a limited time |
| **Check** | at **Unlock** | only what it costs you to open the lease |

The vault fills up even while the UI says *Locked*: capture does not need a
lease, only injection does. Non-exportability comes from `ExportPolicy.None` on
the TPM key, not from the presence mode.

## Vault engine

TPM 2.0 is not universal. Older workstations, virtual machines without a vTPM,
and anything still on TPM 1.2 have none — and on those the application used to
refuse to run at all, which is not protection but absence. AES-GCM, by contrast,
works on every CPU and has been hardware-accelerated since about 2010.

So the engine is a choice:

| Engine | Uses | Claim |
|---|---|---|
| **Automatic** (default) | TPM if the machine has a usable one, software otherwise | whichever it got — stated in the header |
| **TPM 2.0 only** | TPM, or nothing | the vault cannot be opened on another machine |
| **Software AES-256-GCM** | any CPU | the cookie is never in the browser profile; nothing survives exit |

The software engine gives up **machine binding** and keeps everything else. It
is worth being exact about what that costs, because it is less than it sounds:
against the attack this project was built for — an infostealer reading the
browser's cookie database off disk — the two are equally effective, since the
protection comes from the cookie never being written there. What the TPM adds is
that a copy of a *persisted* vault is useless elsewhere, and the vault does not
persist yet.

What the software engine cannot offer is non-exportability. The key is in
process memory, so anything that can read that memory has it. No software
implementation on any operating system can do otherwise.

**Automatic never downgrades silently.** When it falls back, the header reads
`SOFTWARE VAULT — not sealed to this machine`, the sealer line names the reason,
and the log records it. Choosing `TPM 2.0 only` makes the application refuse
rather than fall back.

### Where the TPM cost actually was

Sealing wrapped a data key per cookie, so unsealing cost one TPM decryption
*per cookie, per request* — twenty-four of them to build one Cookie header for
TikTok. That is the envelope layout, not the chip. The default is now one data
key, unwrapped once when the vault opens; per-request work is AES-GCM alone, and
the TPM is asked once per run.

The per-cookie layout is still used for `TPM consent prompt (per use)`, because
there the prompt per unwrap *is* the point.

## Presence modes

| Mode | At Unlock | While browsing |
|---|---|---|
| **Windows Hello gesture** | biometric or PIN gesture | nothing |
| **TPM consent prompt (per use)** | a click | a Windows prompt **per cookie, per request** |
| **None** | a click | nothing |

The per-use prompt is a property of the TPM key (`CngUIPolicy.ProtectKey`), not
of an application setting, so the selected mode determines how the key is
created. A key made by an earlier run keeps its own policy; the UI reports the
mismatch and **Reset key** recreates it. That makes the current vault contents
unreadable, which costs nothing beyond the current session since the vault is
in-process anyway.

TPM consent is a genuinely strong per-use authorization and is impractical for
ordinary browsing: a site with three session cookies produces three Windows
dialogs on every HTTP request. Treat it as a mode for occasional access.

Windows Hello is an experimental integration and may fail on some machines;
`None` lets the rest of the prototype be exercised without it.

## Browser notes

SessionGuard sets the Windows system proxy.

| Browser | System proxy | Certificate store |
|---|---|---|
| **Edge** | works (tested) | Windows — nothing to do |
| **Brave** | works (tested) | Windows — nothing to do |
| **Chrome** | expected to work; same engine, not separately tested | Windows — nothing to do |
| **Firefox Nightly** | **did not take effect** (tested) — set the proxy manually | its own — see below |

**Firefox then needs two manual steps**, and they fail in an order that hides
the second one: traffic has to reach the guard before a certificate can be
presented at all.

1. **Set the proxy by hand.** *Network Settings → Manual proxy configuration*,
   `127.0.0.1` port `28080`, with *Also use this proxy for HTTPS* ticked.
2. **Trust the certificate.** Firefox keeps its own store, so the root installed
   into Windows means nothing to it. Either set
   `security.enterprise_roots.enabled` in `about:config`, or use **Export CA**
   and import the file under *Authorities*.

### Reading the evidence

The two failure modes look identical from the browser, and the log separates
them:

```text
registry now says: system proxy ON -> 127.0.0.1:28080   <- the write went through
connections since turn on: 0                            <- and nothing is using it
```

The first line rules SessionGuard out. The second names the browser.

Chromium-based browsers read the WinINET configuration and act on the change
notification. Firefox resolves the system proxy by a different route, and on the
machine tested — Firefox **Nightly**, a pre-release build — it never applied the
setting: `network.proxy.type = 5`, Firefox started *after* the guard, the
registry confirming the proxy was on, and not one connection arriving, while
every other application on the same machine went through it. Whether release
Firefox behaves the same has not been established. The manual setting removes
the step entirely and works immediately.

**Start the browser after turning the guard on.** Browsers read the proxy
setting at startup and some never notice a later change. The Unlock button warns
when the browser you picked is older than the guard.

The browser selector identifies browser processes structurally and pins the
lease to the selected process and its descendants. This matters because
Chromium normally makes network connections from a child network-service
process rather than from the visible browser process itself.

## Important limitations

- HTTP/2 is not supported by the interception path; protected traffic is kept
  on HTTP/1.1.
- TLS pinning can break interception. Only explicitly configured hosts are
  intercepted.
- `localStorage` and IndexedDB tokens are outside the proxy's cookie model.
- Cookies without `HttpOnly` are deliberately not protected. A site that keeps
  its session in a script-readable cookie cannot be protected by this design.
- The vault is in-process and is lost when SessionGuard exits.
- Process lineage is a defence-in-depth mechanism, not a perfect boundary
  against malware already running as the same Windows user.
- The local CA gives the application the ability to intercept configured TLS
  hosts; protect the Windows account and SessionGuard installation accordingly.
- TPM consent mode prompts once per cookie per request, which is impractical for
  continuous browsing — and every prompt left unanswered counts against the
  TPM's dictionary-attack defence, which will eventually lock the vault out.
  Over Remote Desktop the prompts may not appear at all while still counting.
- Windows Hello presence is not yet working reliably; treat it as unfinished,
  and note it cannot work over Remote Desktop at all.
- The software vault engine is not bound to the machine; its key is in process
  memory.
- The project has not undergone an independent security audit.

## Testing

The end-to-end suite is a console application rather than a unit-test project,
so it is run, not tested:

```powershell
dotnet run --project .\tests\SessionGuard.E2E
```

`dotnet test` reports no tests for this solution: no test framework is
referenced. The suite drives a real proxy, a real mock service and real separate
OS processes, and prints its own results — 40 checks at present.

It adds temporary hosts-file entries and currently handles only the Unix path,
so on Windows add these to `C:\Windows\System32\drivers\etc\hosts` first:

```text
127.0.0.1 api.example.test
127.0.0.1 other.example.test
127.0.0.1 login.sg.test
127.0.0.1 api2.sg.test
```

Core and the suite build and run on any .NET 8 platform. The Windows project
needs Windows tooling; five of its files are additionally type-checked against
`net8.0` in isolation, and `WindowsHello.cs` plus the XAML are only validated by
building on Windows.

## Security model in one sentence

**The browser should not possess the protected session credential as ordinary
browser state; SessionGuard keeps it local, hardware-bound and policy-gated,
then supplies it only at request time.**

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).

The Apache-2.0 grant includes an explicit patent licence, which matters here
because this implementation accompanies protocol work; and, like every licence
in this family, it disclaims warranties. That disclaimer is not a formality for
a security prototype — see the limitations above.
