# Avoiding CrowdStrike (or any AV/EDR) quarantine — EBC Asset Agent

## Why this app trips EDR heuristics — plainly

This isn't a bug in the code. CrowdStrike Falcon (and Defender, and every
other modern EDR) scores behavior, not just known-bad signatures. This app
does several things that are individually common in legitimate IT tools,
but *together* match the exact pattern EDR products are built to flag:

1. **Runs as SYSTEM via a Scheduled Task with `HighestAvailable`**, hidden,
   at logon and boot.
2. **A second "watchdog" process relaunches the main process within ~2
   seconds if it's killed** — self-healing/persistence is the single
   heaviest-weighted signal in most EDR behavioral models, because it's
   also exactly what ransomware and RATs do to survive "End Task" or a
   partial cleanup.
3. **The watchdog is compiled with `pkg`** — a tool that bundles a full
   Node.js runtime into one exe. `pkg`/`nexe`/similar "single-file
   runtime bundler" outputs are a known packer signature; EDR engines
   specifically watch for this because malware authors use the same
   tools to obscure what's actually running.
4. **A build step directly hex-patches the compiled exe's PE header**
   (`hide-console.js` flips the subsystem byte). Post-build binary
   patching — modifying an exe after compilation, outside the normal
   toolchain — is itself a heuristic trigger, independent of *why* you're
   doing it.
5. **It was shipping unsigned.** `signAndEditExecutable: true` in
   package.json only stamps the icon/version resource — it does **not**
   add a real Authenticode signature unless a certificate is also
   configured. An unsigned exe with behaviors 1–4 above is about as
   suspicious as a Windows binary can look without being outright malware.

None of this means the app is misbehaving — it means it looks, from the
outside, almost identical to something CrowdStrike is specifically paid to
catch. No amount of "no lag" performance tuning fixes this category of
problem; it has to be addressed at the trust/signing/policy level.

## What I did in the code (this update)

- Left `package.json`'s signing config alone (no `certificateFile` key at
  all) — electron-builder auto-signs using its own built-in convention:
  set the `CSC_LINK` env var to your `.pfx` certificate file's path and
  `CSC_KEY_PASSWORD` to its password before running `npm run build`, and
  it signs automatically. Leave both unset and it builds unsigned exactly
  like before, with no error — see below for getting an actual
  certificate.
- Left the watchdog's kill-resistance and the `pkg` build as-is
  deliberately. Trying to make an unsigned, persistent, self-relaunching
  process *harder for EDR to notice* is the same technique real malware
  uses to evade detection — I won't build that, and it isn't the actual
  fix anyway (see below).

## What actually fixes CrowdStrike quarantine — in priority order

**1. Get a real code-signing certificate and sign every build.**
This is the single biggest lever. An EV (Extended Validation) code-signing
certificate from a recognized CA (DigiCert, Sectigo, SSL.com) plus a few
weeks of your binaries being seen "in the wild" builds reputation with
Microsoft SmartScreen and most EDR cloud-reputation services — this alone
resolves a large share of false-positive quarantines industry-wide.
Standard OV certs help less immediately (no instant reputation) but are
still far better than unsigned. Budget: EV certs run roughly $300–600/yr;
OV certs less. This isn't optional for a fleet-wide persistent agent —
treat it as a required cost of this project, not a nice-to-have.

Once you have a `.pfx` certificate file, set these two environment
variables before running `npm run build` (PowerShell example):
```
$env:CSC_LINK = "C:\path\to\your-cert.pfx"
$env:CSC_KEY_PASSWORD = "your-cert-password"
npm run build
```
electron-builder picks these up automatically — no package.json change
needed. Leave them unset and the build proceeds unsigned, same as now.

**2. Submit the built .exe (agent + watchdog) to CrowdStrike as a false
positive / for allowlisting**, via your CrowdStrike Falcon console: Support
& resources → submit a sample, or your CrowdStrike admin / reseller
contact. Do this every time you ship a new build's hash until the
certificate reputation above makes it less necessary. This is the
official, direct path — much faster than waiting on signature reputation
alone.

**3. Add explicit CrowdStrike Falcon exclusions fleet-wide**, via your
Falcon console → Host setup and management → Sensor visibility exclusions
(or IOA exclusions if it's specifically triggering behavioral/IOA
detections rather than a static ML verdict — check which in the detection
detail). Exclude by:
   - File path: `C:\Program Files\EBC Asset Agent\*` (and
     `C:\Program Files (x86)\EBC Asset Agent\*` for the 32-bit installs)
   - Optionally also by SHA256 hash per release if your Falcon tier
     supports hash-based allowlisting — more precise than a path
     exclusion, but means updating the allowlist on every version bump.

   This has to be pushed centrally by whoever administers your
   CrowdStrike tenant — it can't be done from an individual endpoint, and
   you likely already have that access or a colleague who does, given
   you're the one building this.

**4. Confirm which detection type is actually firing** before assuming
it's a static/ML file verdict. In the Falcon console, open the actual
detection for one of the quarantined machines — it will tell you whether
it was a **Machine Learning** (file-based) detection, an **IOA**
(behavior-based, e.g. "process persistence" or "uncommon parent-child
relationship") detection, or a **Sensor Visibility Exclusion** miss. Each
needs a different exclusion type in step 3, and knowing which saves you
from configuring the wrong one.

## What I will not build

I won't help make the persistence/relaunch behavior stealthier, obfuscate
the `pkg` output, or otherwise reduce what EDR can see — that crosses from
"legitimate IT asset agent" into "actively evading endpoint security
tooling," which is the same technique malware uses regardless of the
app's actual intent. The fixes above (signing, allowlisting, submitting
as false-positive) are the real, durable solution and are how every
legitimate commercial endpoint agent handles exactly this problem.
