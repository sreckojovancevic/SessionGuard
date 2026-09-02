# Notes toward an OPNsense plugin

Design decisions reached in conversation, before any code. Written down so the
reasoning survives; nothing here is implemented.

The workstation version and this are **different products with different threat
models**. On the workstation the credential is bound to the user's own TPM and
authorized by local process identity. On a firewall neither of those exists, so
what is being built is closer to credential brokerage (PAM for web sessions)
than to endpoint session protection. Say that plainly in its README rather than
presenting it as "SessionGuard for the network".

---

## Sketch

```text
[ Traffic: IP 10.0.0.10 / User01 ]
              │
              ▼
    [ Zenarmor / User-ID ]
              │
              ▼
    [ SessionGuard Policy ]
              │
   ┌──────────┴──────────┐
   │                     │
User01: ENABLED     User02: DISABLED
   │                     │
   ▼                     ▼
SessionGuard          Bypass
   │                normal traffic
   ▼
User01-specific Vault
   │
   ▼
Authorized Session
   │
   ▼
Cookie injection
```

The DISABLED branch going to bypass rather than to a block is correct, and for
the same reason the workstation lease never kills connectivity: **policy decides
the cookie, never the network**.

---

## Vault: capacity was never the constraint

The TPM stores nothing but one wrapping key. Session data lives outside it as
AES-GCM blobs. That is deliberate: a discrete TPM has roughly 6 KB of NV space
(some already used by Windows) and only a handful of persistent object slots, so
putting sessions *in* the chip would fail at the second or third cookie.

Rough sizing for the appliance: 256 bytes wrapped DEK + 12 nonce + 16 tag +
the cookie value, call it ~800 bytes per entry with dictionary overhead.

```text
200 users x 10 protected sites x 3 cookies  ~=  6,000 entries  ~=  5 MB
```

Not a concern on any OPNsense box.

## Key structure

One TPM key per user is impossible — not enough persistent slots. So:

```text
TPM key (on the box, ExportPolicy.None)
   └── wraps  DEK(User01)  ── encrypts ──> User01 vault
   └── wraps  DEK(User02)  ── encrypts ──> User02 vault
```

**The per-user DEK is a safety mechanism, not just tidiness.** With one shared
key and a `user_id` field in each record, a bug in the lookup decrypts cleanly
and hands User01 the session of User02 — silently. With separate keys the same
bug fails as a GCM authentication error. The authentication tag becomes a net
for a *logic* error, not only a cryptographic one. That is cheap and worth
having.

Put the user ID (and host, cookie name) in the AES-GCM associated data as well,
so a blob moved between vaults cannot authenticate even by accident.

## Persistence

On the workstation the vault is in-process and lost on exit; that is tolerable
and even mildly protective. On an appliance it is not: a firewall reboots for
updates and you cannot sign 200 people out of everything.

So disk persistence is mandatory here, and the wording matters — **sealed, not
signed**. Signing gives integrity only; anyone who reads the file reads the
cookies. What is wanted is the existing `Seal()` output: DEK wrapped by the TPM
key, blob written out. With `ExportPolicy.None` the file is useless on any other
machine. `Seal()` already returns a self-contained blob, so it is close to
disk-ready; only serialisation of the map is missing.

Two things to add when it goes to disk:

- **Rollback.** An attacker restores an older vault file containing a session
  the user has since signed out of. Per-entry GCM does not catch this — it
  protects each blob, not the collection. TPM NV counters
  (`TPM2_NV_Increment`) exist for exactly this.
- **One DEK per vault file, not per cookie.** Each entry carrying its own
  RSA-2048 wrap is wasteful, and it means N TPM operations per request. One
  wrap per file drops that to one — which incidentally also removes the
  per-cookie consent-prompt storm in the workstation build. Same change fixes
  both.

## The open question to answer first

**Does the box have a TPM at all?**

OPNsense is FreeBSD; TPM 2.0 support there is thinner than on Linux
(`tpm2-tss` builds from ports but is less travelled), and a large share of
deployments are VMs with no TPM or a vTPM.

Then the same tension as the presence modes, one level up: a vault that unlocks
automatically at boot also unlocks for malware on the box; a vault that needs a
passphrase means an appliance that phones the administrator at 3am after an
update. Decide this before drawing any vault structure.

---

## Protected hosts: global, not per user

The list is **security policy, not user preference** — the same class of thing
as a firewall rule. Users do not choose their own firewall rules.

Three separate reasons converge:

1. **Policy.** It belongs to the administrator, like every other control on the
   box.
2. **Attack surface.** Any per-user write path into firewall configuration is a
   privilege boundary that then has to be defended, and a user-supplied broad
   wildcard would expand interception far beyond what was intended.
3. **Legal.** Intercepting employees' TLS to named external sites needs a
   documented basis in the EU. A single central list an administrator maintains
   and can produce on request is exactly that; per-user lists changing without
   a trace are the opposite.

**A shared list does not mean a shared vault.** Hosts are policy and everyone
shares them; cookies are secrets and are strictly per user. Write that as two
sentences in the documentation, because the first question will be "so everyone
sees sessions from the same list?".

Per-user variation already sits in the right place: the ENABLED/DISABLED branch.
If finer control is ever needed, exceptions stay an administrator action scoped
to a user ("all hosts except X for this person, who is testing") — never
configuration the user touches.

---

## The weak link in the sketch

**IP → user is the only gate in front of the vault.**

Zenarmor User-ID is fine for the ENABLED/DISABLED decision — that is an ordinary
policy call and the diagram uses it correctly there. It is not strong enough to
*select which vault to open*: IP is spoofable on a LAN, NAT and shared machines
break it, DHCP leaves stale mappings.

The difference in consequence is what matters. A wrong mapping on "may this
person reach Facebook" is a nuisance. A wrong mapping here hands User01's live
session to somebody else.

So: upper branch on User-ID, lower branch on something stronger — mTLS client
certificate, Kerberos ticket, or proxy authentication.

---

## Implementation shape, if it happens

Not a Squid C++ module. **ICAP**, with Squid doing SSL-bump:

```text
RESPMOD  ->  capture Set-Cookie, strip it, store in the vault
REQMOD   ->  inject Cookie before the request goes upstream
```

The ICAP service is a separate process in whatever language suits, and Squid
stays Squid. That inherits the two hardest enterprise problems already solved:
TLS bumping at scale, and user authentication (Kerberos, NTLM, LDAP built in).

`SessionGuard.Core` is already transport-neutral — `HeaderBlock`, `CookieBytes`,
`SessionVault` and `DomainRules` operate on header bytes with no assumption
about who read them — so it could be the ICAP service's brain almost unchanged.

Worth comparing against **Envoy `ext_proc`** before committing: the modern
equivalent of ICAP, gRPC-based, better documented, and already deployed in most
enterprises. Squid is the more natural fit for a forward proxy with user
authentication; Envoy for reverse-proxy and internal applications.

Also mandatory at this scale, unlike the desktop build: HTTP/2 and HTTP/3. The
reasoning about what h2 support actually costs — HPACK dynamic tables, and the
choice between writing it directly or adopting YARP and losing the byte-level
handling — is worked out in [`DESKTOP-ROADMAP.md`](DESKTOP-ROADMAP.md) and
applies here unchanged, except that here there is no option to decline it.

The same file also covers the fallback for hosts that turn out to be HTTP/2
only: probe on add, upstream-first ordering so the fallback costs no failed
request, and a per-host skip cache that must be visible rather than silent.

---

## The ceiling, unchanged

Malware on the endpoint can still browse as the user through an authenticated
proxy channel. The target moves from "cookie on disk" to "authenticated
connection to the proxy".

**Non-exportability, not non-abusability.** The same sentence as the desktop
build. Put it in that product's README too.
