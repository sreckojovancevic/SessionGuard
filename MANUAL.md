# SessionGuard — User Manual

This manual explains how to build, start, configure and use the current Windows
prototype.

> **Experimental software:** this is a security prototype, not an audited
> security product. Read the limitations before using it with an important
> account.

---

## 1. What SessionGuard is doing

Normally a browser stores a session cookie in its profile:

```text
login
  -> Set-Cookie
  -> browser cookie jar
  -> every later request carries Cookie:
```

SessionGuard changes that path for explicitly protected hosts:

```text
login
  -> Set-Cookie
  -> SessionGuard captures it
  -> local TPM-backed vault
  -> browser does not keep the protected session cookie

later request
  -> SessionGuard checks the local lease/process policy
  -> Cookie header is added immediately before upstream delivery
```

Hosts that are not protected are not intercepted:

```text
browser -> CONNECT tunnel -> Internet
```

---

## 2. First build

Open PowerShell in the repository root.

### Normal build

```powershell
dotnet build .\SessionGuard.sln -c Release
```

### Run from source

```powershell
dotnet run --project .\src\SessionGuard.Windows -c Release
```

### Self-contained Windows x64 package

This creates a publish directory containing the executable and the required
.NET runtime files:

```powershell
dotnet publish .\src\SessionGuard.Windows `
  -c Release `
  -r win-x64 `
  --self-contained true
```

Output:

```text
src\SessionGuard.Windows\bin\Release\
net8.0-windows10.0.19041.0\
win-x64\
publish\
```

The executable is:

```text
SessionGuard.exe
```

For Windows ARM64:

```powershell
dotnet publish .\src\SessionGuard.Windows `
  -c Release `
  -r win-arm64 `
  --self-contained true
```

No solution or source-file changes are required just to select x64 versus
ARM64 at publish time.

---

## 3. Starting SessionGuard

Start the application with:

```powershell
dotnet run --project .\src\SessionGuard.Windows -c Release
```

or launch `SessionGuard.exe` from the publish directory.

The application is per-user. It modifies the current user's Windows Internet
Settings and current-user certificate store.

If a previous run died while the system proxy was enabled, SessionGuard looks
for its saved proxy-state marker at startup and attempts to restore the previous
settings before doing anything else.

---

## 4. Configure the hosts you want to protect

In the **Protected hosts** box enter the hostname(s) to intercept.

Examples:

```text
example.com
```

or:

```text
login.example.com, api.example.com
```

or:

```text
*.tiktok.com
```

Press **Save**.

### Host syntax

Use hostnames, not schemes or paths. The UI accepts common pasted URL forms and
normalizes them, so these can be entered as well:

```text
https://example.com/login
example.com:443
```

A plain entry is exact:

```text
example.com
```

A wildcard entry beginning with `*.` covers the bare domain and its
subdomains:

```text
*.example.com
```

The stored file is:

```text
%LOCALAPPDATA%\SessionGuard\protected-hosts.txt
```

If you change the host list while the Guard is already on, turn the Guard off
and on again. The UI reports this explicitly.

### What Save checks

Pressing **Save** probes each host with a single TLS connection offering only
HTTP/1.1, and reports what it found:

```text
tiktok.com — HTTP/1.1 accepted
some.host — requires HTTP/2, cannot be protected yet
```

A wildcard entry is probed at its bare domain, which is all that can be checked
without guessing subdomain names. The result is therefore an observation, not a
promise: it says nothing about subdomains reached later, about certificate
pinning (enforced by the client, so a handshake reveals nothing about it), or
about a site that keeps its session in `localStorage` rather than in cookies.

### Hosts that cannot be intercepted

A subdomain discovered while browsing may refuse HTTP/1.1 even though the bare
domain accepted it. SessionGuard establishes the upstream connection *before*
completing the TLS handshake with the browser, so when that happens it can fall
back to a plain tunnel from the first byte — the request succeeds and nothing
visibly fails.

Such a host is then remembered for an hour and passed straight through, and the
UI says so:

```text
1 host(s) passing through UNPROTECTED: webcast.example.com — requires HTTP/2
```

That line is deliberate. The traffic works, but it is not protected, and a
silent skip would be a silent hole.

---

## 5. Turn the Guard on

> **Start the browser after this, not before.** Browsers read the Windows proxy
> setting when they start, and some never notice a later change — Firefox caches
> it, and a Firefox that believes there is no proxy also enables HTTP/3, so its
> traffic leaves over UDP and cannot reach the guard at all. A browser that was
> already running may therefore bypass SessionGuard completely while everything
> in the application reports success. Since version 19 the Unlock button says so
> when the browser you picked is older than the guard.
>
> The whole working order is: **Turn on → start the browser → Refresh → Unlock →
> then sign in.**

Press **Turn on**.

The sequence is:

1. It ensures the local SessionGuard root CA is trusted by the current Windows
   user. On first use you will be asked for consent.
2. It starts the local proxy on:

   ```text
   127.0.0.1:28080
   ```

3. It changes the Windows user's system proxy to that endpoint.
4. All traffic using the Windows system proxy now passes through SessionGuard.

The TPM-backed vault is opened earlier, when the application starts — not here.
If it is unavailable, **Turn on** is disabled from the outset and the header
reads `PROTECTED MODE UNAVAILABLE`.

The application saves the previous proxy settings before changing them.

### Verify the proxy

In PowerShell:

```powershell
Get-NetTCPConnection -LocalPort 28080 -ErrorAction SilentlyContinue |
    Format-Table LocalAddress,LocalPort,State,OwningProcess
```

You should see a `Listen` entry for `127.0.0.1:28080`.

You can also inspect the current user's WinINET settings:

```powershell
Get-ItemProperty `
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
  Select-Object ProxyEnable,ProxyServer,ProxyOverride
```

Expected while the Guard is on:

```text
ProxyEnable : 1
ProxyServer : 127.0.0.1:28080
```

---

## 6. Browser selection

Start the browser before pressing **Refresh**.

SessionGuard scans for known browser process names:

```text
chrome
msedge
brave
vivaldi
opera
opera_gx
firefox
```

It does **not** use `MainWindowHandle` as the selector. Instead it builds a
process tree and offers browser roots to the user.

A typical result looks like:

```text
28 browser process(es), 2 root(s)
```

The browser selector is editable. If automatic enumeration ever fails, read
the PID from **Task Manager -> Details** and type it directly.

### Why the root process matters

Chromium browsers commonly have several processes. The process owning the
actual socket can be a child network-service process. SessionGuard therefore
authorizes the selected browser process **and its descendants**, while still
rejecting an unrelated process.

The lease is also pinned to the selected process's identity and start time so a
recycled PID does not automatically inherit the old lease.

---

## 6a. Vault engine

The **Vault** selector decides what seals the vault. It is a separate question
from **Check**, which decides what proves a person is present.

| Engine | Uses | Available |
|---|---|---|
| **Automatic** (default) | TPM if usable, software otherwise | always |
| **TPM 2.0 only** | TPM, or refuses to run | machines with TPM 2.0 |
| **Software AES-256-GCM** | any CPU | always |

**Why the choice exists.** TPM 2.0 is not universal — older workstations,
virtual machines without a vTPM and TPM 1.2 machines have none, and on those the
application would otherwise refuse to start. AES-GCM runs everywhere, and is
hardware-accelerated on anything since roughly 2010.

**What the software engine gives up: machine binding, and nothing else.**
Against the attack this was built for — an infostealer reading the browser's
cookie database off disk — the two engines are equally effective, because the
protection comes from the cookie never being written there. When the application
exits, the software key and everything it held are gone, so a powered-off
machine holds nothing at all.

What it cannot offer is non-exportability. The key sits in this process's
memory, so anything that can read that memory has it, along with every entry in
the same snapshot. A TPM key is created inside the chip and cannot be read out
even by the process using it — a property no software implementation can
provide, on any operating system.

**Automatic never downgrades quietly.** On fallback the header reads:

```text
SOFTWARE VAULT — not sealed to this machine
```

and the sealer line and the log both name the reason. If a machine should refuse
to run rather than protect less, set the engine to **TPM 2.0 only**.

**Changing the engine changes the key**, so the vault becomes unreadable and you
will be signed out of protected sites. The application asks before doing it.

### Two reasons to choose Software on a machine that has a TPM

Both were met in practice, not in theory:

1. **The TPM locked itself out.** Repeated per-use consent prompts left
   unanswered trip its dictionary-attack defence, after which nothing opens —
   including **Reset key**, which has to open the key in order to delete it.
2. **Remote Desktop.** Consent prompts may never be displayed in a remote
   session while still counting as failed authorizations, and Windows Hello
   cannot work there at all.

### Where the TPM cost actually was

Sealing wrapped a data key per cookie, so unsealing cost one TPM decryption *per
cookie, per request* — twenty-four of them to assemble one Cookie header for
TikTok, and in consent mode twenty-four dialogs. That was the envelope layout,
not the chip.

The default is now one data key, unwrapped once when the vault opens and held in
memory; per-request work is AES-GCM alone. The TPM still binds the vault to this
machine, but is asked once per run instead of per use.

The per-cookie layout is kept for **TPM consent prompt (per use)**, where a
prompt per unwrap is exactly what was asked for. That is the honest trade, and
it is why the two live side by side: *the fast path turns per-use consent into
per-run consent.*

---

## 7. Presence / Unlock policy

### Three independent layers

The most common misunderstanding is that the **Check** setting decides whether
your session is protected. It does not. Three separate things are going on.

**Layer 1 — the vault, and non-exportability.** Active whenever the Guard is on
and the host is in your list. Independent of the Check setting and of whether a
lease is open. `Set-Cookie` is captured, sealed with the TPM key and removed
from the response, so the browser profile never holds it. Non-exportability
comes from `ExportPolicy.None` on the TPM key.

> You will see the Vault fill up while the UI still says **Locked**. That is
> correct: capture does not need a lease.

**Layer 2 — the lease.** Decides whether a stored cookie is put *back* into
outgoing requests, for whom, and for how long. It is pinned to the browser
process you select **and all of its descendants** — not to a tab, a site or a
login. One lease covers the whole browser and every protected host at once.

Descendants matter: Chromium makes its connections from a child
network-service process, so pinning only the visible process would reject the
browser you just authorized.

**Layer 3 — the Check setting.** Decides only what it costs you to open the
lease. It does not change the vault, non-exportability, or the reach of the
lease.

| Check | At Unlock | While browsing |
|---|---|---|
| **Windows Hello gesture** | biometric or PIN gesture | nothing |
| **TPM consent prompt (per use)** | a click | a Windows prompt per cookie, per request |
| **None** | a click | nothing |

### The Check setting drives the TPM key policy

The per-use prompt is a property of the TPM key (`CngUIPolicy.ProtectKey`), not
of an application setting. Selecting a mode therefore determines how the key is
created:

```text
Windows Hello    -> key without UI policy
TPM consent      -> key with per-use ProtectKey policy
None             -> key without UI policy
```

A key created by an earlier run keeps its own policy regardless of what the UI
now says. When that happens the sealer line reports the mismatch, for example:

```text
key has per-use consent, mode wants no per-use consent
```

Press **Reset key** to delete the TPM key and recreate it for the selected mode.
This makes anything currently in the vault unreadable, so you will have to log
in to protected sites again. Since the vault is in-process and lost on exit
anyway, that costs nothing beyond the current session.

### Practical note on TPM consent

The prompt fires on every private-key operation, and the vault unseals **once
per cookie per request**. A site with three session cookies therefore produces
three Windows dialogs for every HTTP request. This is a deliberate, very strong
per-use authorization, and it is not usable for ordinary browsing. Treat it as
a mode for occasional, high-value access rather than a daily default.

**It can also lock the TPM out of your own vault.** Every prompt that is asked
for and not answered counts, to the chip, as a failed authorization — whether
you dismissed it, or it never appeared because the session is a Remote Desktop
one. Enough of them and the TPM's dictionary-attack defence starts refusing:

```text
no TPM-backed key: The Platform Crypto Device has ignored the authorization
for the provider object, to mitigate against a dictionary attack.
```

Nothing is damaged and no key is lost; the chip is declining to answer for a
while. Note that `Get-Tpm` will still report `LockedOut : False` — that field is
about owner authorization, while the Platform Crypto Provider keeps its own
counters. `LockoutCount` is the number that matters, and `LockoutHealTime` is
how long one count takes to decay.

To recover:

1. **Wait**, or clear it with `Reset-TpmLockout` (needs owner authorization).
   **Never `Clear-Tpm`** — that wipes every TPM key on the machine, BitLocker
   and Windows Hello included.
2. Then set **Check** to `None` and press **Reset key**, so the new key carries
   no per-use consent and cannot trigger this again.

Step 2 has to come second: **Reset key** must open the existing key in order to
delete it, so it fails the same way while the chip is still refusing.

### Windows Hello

If verification fails, the lease remains closed. SessionGuard does not silently
downgrade to an unverified lease.

> The current Windows Hello integration is experimental. If it does not work on
> your machine, use None while testing the rest of the system.

### None

Unlock is an ordinary button click. This does **not** remove the rest of the
authorization model. The lease still:

- expires after the configured period,
- is pinned to the selected process,
- follows the process lineage rules,
- controls whether protected session cookies are injected.

What is missing is proof that a person did it. Malware able to drive the UI, or
malware that simply waits for you to unlock, rides on the open lease.

## 8. Unlocking a browser

> **A locked lease is not a safe idle state — it signs you out.** With the guard
> on and the lease shut, guarded cookies are taken out of the browser and never
> put back, so every request to a protected site goes out without its session.
> The site answers the way it answers a stranger: 401, 403, a login page, or an
> anti-automation message such as *"Maximum number of attempts reached"*, which
> looks nothing like a proxy problem.
>
> Nothing is broken when this happens; it is the design behaving as written. But
> it is invisible from the browser, so the lease panel now counts it:
>
> ```text
> LOCKED — 201 request(s) sent without their session.
> Protected sites will act signed-out until you press Unlock.
> ```
>
> **Sign in only after the lease is open.** Signing in while it is shut sends the
> whole login flow out unauthenticated; the session cookies are captured into
> the vault and then never returned, and the site sees an endless series of
> half-authenticated attempts.

After selecting the browser and the desired presence policy, press **Unlock**.

A successful unlock opens the lease for the configured duration (15 minutes by
default in the current prototype).

The UI will show something similar to:

```text
Unlocked for pid 6068 and its children — 14:59 remaining
```

When the lease expires:

```text
Locked — requests go out without the session
```

This is intentional. **Expiration of the lease must not disconnect the browser
from the Internet.** It only stops SessionGuard from attaching the protected
session credential.

---

## 9. Log in to a protected site

Once the Guard is on and the browser lease is open:

1. Navigate to a hostname listed under **Protected hosts**.
2. Log in normally.
3. The site's `Set-Cookie` response is parsed by SessionGuard.
4. Session cookies are stored in the vault rather than left in the browser's
   ordinary cookie jar.
5. Later requests from the authorized browser process receive the appropriate
   `Cookie` header at the proxy immediately before upstream delivery.

The **Vault** panel should change from:

```text
empty
```

to entries such as:

```text
example.com: sessionid, csrf
```

The exact cookie names depend on the site.

---

## 10. Cookie scope and logout

SessionGuard models the important cookie scope rules needed for this design.

### Which cookies are taken at all: `HttpOnly`

**SessionGuard vaults a cookie only if the server marked it `HttpOnly`.**
Everything else is passed to the browser exactly as the server sent it, and the
Vault panel names what was left behind:

```text
left with the browser (script-readable, not HttpOnly): tiktok.com:msToken
```

`HttpOnly` is the server's own statement that the page's JavaScript never reads
this cookie — which is precisely the condition under which removing it from the
browser is invisible to the site. Without the attribute, the site's own script
may read the cookie, and frequently rewrites it.

The failure this prevents does not look like a cookie problem from the outside.
Large sites carry anti-automation tokens in ordinary script-readable cookies: a
script reads the token from `document.cookie`, signs the next request with it,
and sends the signature along. If the token is in the vault the script reads an
empty string, signs with nothing, and every request from that page is malformed
in the same way. To the server that is not a broken proxy — it is a bot, and
the answer is a rate limit:

```text
Maximum number of attempts reached. Try again later.
```

Nothing real is given up by leaving those cookies alone. **A cookie the page can
read is one that any script on that page can already steal**, so vaulting it
never closed the hole it appeared to close. What it did was break the site.

The claim therefore narrows, honestly: SessionGuard protects credentials the
browser holds and script cannot touch. A site that keeps its session in a
script-readable cookie cannot be protected this way — and could not have been,
by anything that leaves the page working.

One exception keeps sign-out correct: once a name has been vaulted it stays
guarded even if a later `Set-Cookie` for it omits `HttpOnly`. Otherwise a
server's deletion header would pass by and leave a dead credential in the vault
forever.

### Cookies the guard never saw at all — the quiet failure

Worse than a copy left behind is a credential the guard never had a chance to
take. It happens for one reason, and it happened during development more than
once:

> **Signing in before the browser is actually going through the proxy.**

The whole login lands in the browser profile. The guard then works perfectly on
everything afterwards — intercepting, capturing device tokens, injecting — while
the one cookie that matters is the one it never saw. The vault fills with
plausible-looking entries, the site works, and nothing is protected.

There is no way to tell that apart from success by looking at the site. So the
guard says it:

```text
never_captured  www.tiktok.com  sessionid,sid_guard — the browser had these
                before the guard saw them, so they are NOT protected. If any is
                a session cookie, sign out and sign in again with the guard
                running.
```

and the Vault panel turns red:

```text
NOT PROTECTED — 6 cookie(s) the guard never saw: sessionid, sid_guard, ...
```

The distinction it draws is between a cookie the guard *decided* about — vaulted,
left alone as script-readable, or refused for its scope — and one it never
witnessed. The first three are informed outcomes. The fourth is a blind spot.

**The fix is always the same: sign out, then sign in again with the guard
running and the lease open.** Only a fresh `Set-Cookie` can be captured.

### Copies the browser already had

Capturing a cookie from `Set-Cookie` stops it ever reaching the browser — but
only for cookies issued **while the guard was running**. One the browser
already had, from before the guard was ever turned on, is untouched by that.

This is easy to miss, because everything looks correct: the vault holds the
cookie, requests carry the vault's copy because the browser's is stripped on
the way out, and the site works normally — while `sessionid` sits in the
browser profile on disk, exactly where a cookie thief reads it.

The log names it. `stripped_client_cookie` means the browser sent a guarded
name, which means it still has its own copy:

```text
stripped_client_cookie www.tiktok.com  sessionid,sid_guard,sessionid_ss,...
```

SessionGuard now asks the browser to delete those, using the mechanism the site
itself would use — a `Set-Cookie` with `Max-Age=0`, addressed to the same name,
domain and path:

```text
evict_from_browser  www.tiktok.com  sessionid,sid_guard — the vault holds these;
                                    asking the browser to drop its own copy
```

The session does not break: the vault keeps injecting its copy.

Two details, both learned by measurement rather than assumed:

- **Scope has to match.** A browser matches a deletion on name, domain *and*
  path. A host-only deletion leaves a domain cookie of the same name untouched,
  and the reverse. A request header carries only names — RFC 6265 sends no
  scope with them — so there is no way to learn how the browser's copy is
  scoped, and both shapes are sent.
- **A stray deletion is harmless here.** If one lands where no cookie exists it
  creates an empty one; outbound stripping works by name, so that stray is
  removed from the next request and never reaches the site.

If the browser keeps sending a name well after the deletion was sent, it did not
take, and that is reported rather than retried forever:

```text
eviction_ignored  host  name — still in the browser profile after the deletion
                  was sent; these remain readable from disk
```

### Domain

A cookie with:

```text
Domain=.example.com
```

can be used for matching subdomains according to cookie domain matching.

A host-only cookie remains associated with the host that set it.

### Path

A cookie with:

```text
Path=/admin
```

is not sent to:

```text
/cookies
```

### Sign-out

If a service sends an expiry/delete cookie such as `Max-Age=0`, SessionGuard
removes the corresponding vault entry instead of preserving a dead credential.

The expiry header itself is removed along with the other `Set-Cookie` headers:
the browser holds no copy of the protected cookie, so there is nothing there to
delete.

A `Set-Cookie` whose `Domain` the sending host is not entitled to claim is a
different case. SessionGuard refuses to vault it and **passes the header
through untouched**, leaving the decision to the browser. Refusing to store
something must not mean destroying it.

---

## 11. Firefox

Firefox needs two things done to it that Edge and Brave do not. They are
independent, and they fail in an order that hides the second one — traffic has
to reach the guard before a certificate can be presented at all.

### What was actually tested

| Browser | System proxy | Certificate store |
|---|---|---|
| **Edge** | works | Windows — nothing to do |
| **Brave** | works | Windows — nothing to do |
| **Chrome** | expected to work; same engine, not separately tested | Windows — nothing to do |
| **Firefox Nightly** | did not take effect | its own — needs a step |

Two of three Chromium-based browsers were confirmed working, so the Windows
system-proxy mechanism itself is not the problem, and neither is what
SessionGuard writes.

### Telling the two failures apart

They look identical from the browser, so the log separates them:

```text
registry now says: system proxy ON -> 127.0.0.1:28080   <- the write went through
connections since turn on: 0                            <- and nothing is using it
```

The first line rules SessionGuard out. The second names the browser.

### Set the proxy manually. "Use system proxy settings" is not enough.

Firefox's default is to follow the Windows proxy, and in principle that is
correct. In practice, on the machine this was developed against — running
Firefox **Nightly**, a pre-release build — it never applied the setting: with
`network.proxy.type = 5`, a Firefox started *after* the guard, and the registry
confirming `system proxy ON`, **not one connection ever reached the proxy**,
while every other application on the same machine went through it.

Chromium browsers read the WinINET configuration and act on its change
notification; Firefox resolves the system proxy by a different route and caches
the result. Whether release Firefox behaves the same has not been established —
what is established is that the manual setting removes the step entirely and
works immediately.

Setting it by hand works immediately:

```text
Settings -> Network Settings -> Settings…
  -> Manual proxy configuration
     HTTP Proxy:  127.0.0.1     Port: 28080
     [x] Also use this proxy for HTTPS
```

Treat it as the required step for Firefox rather than as a workaround, at least
until someone confirms release Firefox behaves differently.

Edge and Brave follow the Windows setting without any of this.

### Trust the certificate

Firefox also maintains its own certificate store, so the root SessionGuard
installs into the Windows store means nothing to it.

These are two independent walls, and they fail in an order that hides the
second one. Traffic has to reach the guard before a certificate can be
presented at all — so while the proxy is not being used, everything looks like
a proxy problem, and the certificate problem only appears once that is fixed.

If a protected HTTPS site reports a certificate error in Firefox, either:

**1. Let Firefox read the Windows store.** In `about:config`:

```text
security.enterprise_roots.enabled = true
```

Nothing to import; Firefox then sees the root SessionGuard already installed.

**2. Import the certificate by hand.** Press **Export CA** in SessionGuard — it
writes `SessionGuard-root-CA.cer` to the Desktop — then in Firefox:

```text
Settings -> Privacy & Security -> Certificates -> View Certificates
  -> Authorities -> Import -> select the file
  -> tick "Trust this CA to identify websites"
```

Only the public certificate is exported. The private key stays under DPAPI and
never leaves the machine.

Restart Firefox afterwards — and start it **after** the guard is on, or it may
not pick up the proxy setting at all (see section 5).

SessionGuard logs a reminder when Firefox is selected, and the Windows root CA
installation it performs is not by itself enough for Firefox.

---

## 12. Turn the Guard off

Press **Turn off**.

SessionGuard will:

1. restore the user's previous Windows proxy settings,
2. stop the proxy listener,
3. close the active lease.

The proxy state is stored before the registry is changed so that a crash can be
reconciled on the next startup.

If the application is killed hard or the machine loses power, `ProcessExit`
may not run. This is why the persistent recovery marker exists.

---

## 13. Forget all sessions

Press **Forget all** in the Vault panel.

This clears the in-process session vault.

Because the vault is deliberately non-persistent at the application level,
exiting SessionGuard also loses the current session material.

---

## 14. Where SessionGuard stores local state

Current-user data is under:

```text
%LOCALAPPDATA%\SessionGuard\
```

Important files include:

```text
protected-hosts.txt
settings.json
proxy-state.json       # only while a proxy change is active/recoverable
```

The TPM wrapping key is held by the Windows CNG Microsoft Platform Crypto
Provider rather than being exported as an ordinary private-key file.

The local CA private key is protected with DPAPI under the current Windows
account.

Do not copy these files to another machine and expect the vault to work. The
TPM-backed key is intentionally machine-bound.

---

## 15. Development-only insecure mode

If the machine does not have a usable TPM, normal protected mode refuses to
start.

For development/testing only:

```powershell
dotnet run --project .\src\SessionGuard.Windows -c Release -- --allow-insecure-dev-mode
```

The UI will explicitly say that the vault is RAM-only and insecure.

Do not use this mode to protect a real account.

---

## 16. Troubleshooting

### `An attempt was made to access a socket in a way forbidden by its access permissions`

This normally means the listener port is unavailable.

Current port:

```text
28080
```

Check it:

```powershell
Get-NetTCPConnection -LocalPort 28080 -ErrorAction SilentlyContinue
```

If necessary, check Windows excluded port ranges:

```powershell
netsh interface ipv4 show excludedportrange protocol=tcp
```

### Browser list is empty

Press **Refresh** after starting the browser.

If necessary, use Task Manager -> Details and type the browser PID directly.

The scan text and log now report the number of browser processes and roots and
list PID/PPID information for diagnosis.

### Traffic diagnostics

The main window log is also the safe traffic diagnostic log. It records connection
mode, TLS negotiation, HTTP method/path, response status, authorization result,
and cookie **names/actions**. It deliberately does not record cookie values,
request bodies, authorization headers, or query strings.

Examples:

```text
intercept              www.tiktok.com    CONNECT 443
upstream_tls           www.tiktok.com    protocol=Tls13; alpn=http/1.1
client_tls             www.tiktok.com    protocol=Tls13
request                www.tiktok.com    GET /; authorized=True; reason=authorized (pinned process)
client_cookies         www.tiktok.com    passed=msToken,ttwid
stripped_client_cookie www.tiktok.com    sessionid
response               www.tiktok.com    200; closeDelimited=False
left_to_browser        www.tiktok.com    msToken (no HttpOnly)
vaulted                www.tiktok.com    sessionid
```

For an authentication problem, compare two runs: first with only the exact host(s)
protected, then with a wildcard such as `*.example.com`. Save each log with
**Save log**. The useful difference is which additional subdomains became
`intercept`, what HTTP status they returned, and which cookie names were vaulted,
left to the browser, stripped, or injected.

The log is intentionally metadata-only. If a site returns a sensitive value in a
URL path rather than a query string, treat the saved log as sensitive diagnostic
data and delete it after analysis.

### Turning recording off

The **Logging** checkbox above the log stops recording. **Clear** empties what
has been recorded so far.

This affects the log and nothing else. The Guard keeps intercepting, the vault
keeps working, and the Vault panel keeps naming the cookies left with the
browser — a security readout must not disappear because a diagnostic was
switched off.

Off means off, including SessionGuard's own lines about itself. Lines that
occur while recording is off are counted, and the count is shown on resume:

```text
logging resumed — 4192 line(s) were not recorded while it was off
```

so a gap in the log is never mistaken for a quiet period.

Two reasons to switch it off. Per-request tracing on a busy site produces a
line several times per request, which makes a long session's log hard to read
and the window's redrawing noticeable. And a saved log is diagnostic data about
your browsing: leaving recording off when you are not diagnosing anything means
there is nothing to leave behind.

### Guard is on but the protected site does not work

Check:

1. The exact hostname is in **Protected hosts**.
2. The browser is using the Windows/system proxy.
3. The SessionGuard root CA is trusted by the browser.
4. The lease is open.
5. The site does not use certificate pinning.
6. The site stores its authentication token in cookies rather than
   `localStorage`/IndexedDB.

### Sign-in fails with "Maximum number of attempts reached"

Do not assume this means that the password or MFA code was wrong. First compare
the same flow with SessionGuard off, then with only the exact site host(s)
protected, and finally with a wildcard if the wildcard is what caused the
problem.

The traffic log is useful here. Look for:

```text
intercept              <host>
request                <host>
response               <host>
left_to_browser        <host>
stripped_client_cookie <host>
injected               <host>
vaulted                <host>
```

If the exact hosts work but `*.domain.example` fails, the first question is which
additional subdomain became intercepted and returned a different response. Do not
move every cookie into the vault to solve this: script-readable cookies are
intentionally left to the browser.

Note also that the site's rate limit may remain active after the technical cause
has been fixed. Wait for the site's cooldown before repeating the authentication
flow.

### `Could not verify your presence`

This is the current Windows Hello integration failing closed.

For testing, change **Check** to:

```text
None — unlock is just a click
```

TPM consent also avoids the gesture, but replaces it with a Windows prompt on
every cookie of every request, which is impractical for browsing.

Either way this does not mean the TPM vault itself is unavailable: the vault and
its non-exportability do not depend on the presence mode.

### Internet disappears after an abnormal shutdown

SessionGuard is designed to recover a stale proxy marker at startup. If the
machine is already stuck behind a dead proxy, use:

```powershell
Get-ItemProperty `
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
  Select-Object ProxyEnable,ProxyServer,ProxyOverride
```

As an emergency user-level reset, disable the Windows proxy in Windows Settings
or Internet Options, then restart SessionGuard so it can reconcile its marker.

---

## 17. What SessionGuard does not protect

This prototype is intentionally narrower than a general browser-security
system.

It does not prevent code running inside an already-authorized browser from
using the live session. JavaScript does not need to steal a cookie if it can
already perform authenticated actions through the browser.

It does not protect tokens stored in:

```text
localStorage
IndexedDB
service-worker/application state
```

It also does not make a compromised Windows user account trustworthy. PID
lineage is useful defence in depth, but a sufficiently privileged attacker in
the same user context can manipulate process relationships and interact with
local security APIs.

The core property being pursued is narrower:

> **A copied browser profile should not contain the protected session cookie in
> a form that can simply be exported and replayed elsewhere.**

---

## 18. Current test coverage

The end-to-end suite is a console application, not a unit-test project, so it
is run rather than tested:

```powershell
dotnet run --project .\tests\SessionGuard.E2E
```

> `dotnet test` reports no tests for this solution. There is no test framework
> referenced; the suite drives a real proxy, a real mock service and real
> separate OS processes, and prints its own results.

> The suite adds temporary entries to the hosts file and currently only handles
> the Unix path (`/etc/hosts`). On Windows, add these to
> `C:\Windows\System32\drivers\etc\hosts` by hand first:
>
> ```text
> 127.0.0.1 api.example.test
> 127.0.0.1 other.example.test
> 127.0.0.1 login.sg.test
> 127.0.0.1 api2.sg.test
> ```

40 checks currently pass, covering:

- byte-level header editing, including `Cookie` not matching `Set-Cookie`
- `Set-Cookie` parsed to name and value, attributes discarded
- login through the guard; the browser jar left without the session
- several `Set-Cookie` values in one response
- keep-alive: repeated requests on one connection
- `Content-Length` and chunked framing, and a request body containing a header
  line arriving byte-exact
- untouched tunnelled hosts
- no-lease behaviour: 401 from the service, with the connection still working
- process lineage: a descendant authorized, an unrelated process refused
- cookie `Path` scoping
- wildcard hosts: `*.tiktok.com` matching and not over-matching
- cookie `Domain` scoping across subdomains, host-only cookies staying put
- a cookie scoped to someone else's domain refused, its header still delivered
- sign-out via `Max-Age=0`
- vault sealing and round-trip

The Windows GUI and security integration are platform-specific and must be
validated on the Windows machine where they will run.

## 19. Recommended test sequence

For a clean first test, use this order:

```text
1. Build
2. Start SessionGuard
3. Configure one protected host
4. Turn on
5. Confirm 127.0.0.1:28080 is listening
6. Start/refresh browser
7. Refresh browser list
8. Select browser PID
9. Set Check = None for the first end-to-end test
10. Unlock
11. Login to the protected site
12. Check Vault
13. Make several authenticated requests
14. Turn off
15. Confirm system proxy is restored
16. Press Reset key, then repeat with TPM consent
    (expect a prompt per cookie per request)
17. Finally test Windows Hello
```

Starting with `None` isolates the proxy/vault/process path from the experimental
Hello integration. Once that path is proven, enable the stronger presence
policies one at a time — remembering that switching to or from TPM consent needs
**Reset key** to take effect, because the policy lives on the key.
