# Target map

What is actually exploitable on iPhone 16e, and in what order.

The 16e is **A18**. That single fact changes the plan: Apple's Memory Integrity
Enforcement (EMTE, 4-bit tags, synchronous tag checks) ships on **A19 and later**
— iPhone 17, iPhone Air, iPhone 18. On A18 there is no MTE at all. So the
kernel target here does **not** need an MIE bypass. It needs what every
pre-MIE arm64e jailbreak needed:

```
[ sandbox / parser entry ] -> [ kernel r/w ] -> [ PAC ] -> [ persist ]
```

`docs/RESEARCH.md` covers the entry candidates. This file covers the middle.

## Why this is the right version boundary

| build | notes |
| --- | --- |
| 27.0.1 | last build Calif demonstrated a full untethered chain on; **many kernel write bugs still live** |
| 27.1 | iPhone 18 / Duo only, not installed on existing phones |
| 27.2 | 163 CVEs, most of the Hexacon chain closed, including 6+ app-reachable kernel writes |
| 27.2.1 | current; adds the brotli fix |

If the 16e is on 27.0.1 or lower, the middle column of the table below is open.
If it is on 27.2+, those specific bugs are gone and the work starts from a
fresh diff of 27.2.1 against whatever ships next.

## Kernel memory writes reachable from an app, fixed in 27.2

From Apple's iOS 27.2 bulletin (`support.apple.com/en-us/149230`). "App" impact
means no entitlement and no physical access — the same starting position as a
sandboxed process or a parser.

| CVE | component | class | impact |
| --- | --- | --- | --- |
| CVE-2026-112507 | Kernel | OOB write, bounds check | **write kernel memory** |
| CVE-2026-84495 | Kernel | UAF | **write kernel memory** |
| CVE-2026-112696 | Kernel | OOB write, bounds check | corrupt kernel memory |
| CVE-2026-84494 | Kernel | OOB write, bounds check | **write kernel memory** |
| CVE-2026-112689 | AVEVideoEncoder | OOB write, input validation | corrupt kernel memory |
| CVE-2026-112470 / -468 / -469 | AVEVideoEncoder | OOB write, bounds check | corrupt kernel memory |
| CVE-2026-112466 | AVEVideoEncoder | OOB read | read kernel memory |
| CVE-2026-65350 | Kernel | UAF | corrupt kernel memory |
| CVE-2026-112517 | Kernel | UAF | corrupt kernel memory |
| CVE-2026-112514 | Kernel | UAF | corrupt kernel memory |

The AVEVideoEncoder family is the most concrete lead. The trigger is reached
through VideoToolbox from an ordinary app, the field is `NumberOfTemporalLayers`,
and at least one third-party reproduction exists. A kernel OOB **write** from a
sandboxed app is one half of a jailbreak. The other half is turning the write
into a controlled read/write.

Priorities, in order of expected effort:

1. **AVEVideoEncoder `NumberOfTemporalLayers`** — app-reachable, write, public
   trigger shape, fixed in 27.2. Diff the 27.0.1 and 27.2 kexts and read the
   added clamp. This is the shortest path from "CVE text" to "controlled write".
2. **CVE-2026-112507 / -84494** — kernel OOB writes described only as "bounds
   checking". No public trigger. Diff the 27.2 xnu against 27.0.1; the fix will
   name the syscall or mach trap. Slower, but a better primitive if the bounds
   are attacker-controlled.
3. **CVE-2026-112610 / -112611** — CoreGraphics PDF OOB write, the same family
   as 86950. This is the *entry*, not the kernel step. Useful for getting code
   execution inside a parser process.
4. **CVE-2026-111497** — brotli "Node2Shell", network-delivered, in CISA KEV.
   Delivery is proven; the write is not public. Treat as an alternative entry.

## What the primitive has to survive on A18

- **KASLR** — kernel slide, per-boot. Need a leak before a write. `--probe`
  already models what a structural probe needs.
- **PAC** — arm64e function pointers and data pointers are signed. The tree
  already strips, canonicalises and rebinds (`krw/pac.c`); a write primitive
  that lands on a signed pointer needs a signing gadget or a target that does
  not re-sign.
- **SPTM / KTRR** — kernel text and page tables are protected at EL2. Do not
  plan on patching text; plan on data, credentials, or a task port.
- **Zone allocators (kalloc_type)** — same-type only. A UAF is much more
  valuable than a linear overflow here.
- **No MIE on A18** — no tag checks, no tag confidentiality. Every write that
  reaches the address lands.

That last line is the reason this project targets the 16e at all. The Hexacon
chain had to defeat EMTE; ours does not.

## The post-exploitation side is already here

Everything above the primitive is written and tested:

- `krw/exploit.c` — registry; the first candidate that reads `g_mela.kbase`
  correctly wins, everything else is rejected. Drop a new provider in and the
  rest of the pipeline runs unchanged.
- `krw/kbase.c`, `krw/virt.c`, `krw/walk_read.c` — slide resolution, 16K
  4-level walks, VA reads.
- `krw/allproc.c`, `krw/task.c`, `krw/sandbox.c` — cred adoption, pid 1,
  task-port takeover, sandbox label drop.
- `krw/amfi.c`, `krw/patch.c`, `krw/trust.c` — code-signing flags, `b`/`bl`/
  `ret`/`nop` patching with range checks, trust-cache injection.
- `rootfs/` — SSV snapshot switch, rootfs remount, launchd job, re-sign walk.
- `rootfs/install.c` + `bootstrap/sileo.sh` — Sileo bootstrap and
  TrollStore-lite install into `/Applications`.

So the deliverable when a primitive appears is a provider, not a rewrite:

```c
static int my_attach(struct mela_ctx *ctx) { /* fill ctx->ops */ }
MELA_EXPLOIT("ave-temporal-layers", my_attach);
```

`docs/HARDWARE.md` is the contract that provider has to satisfy.

## The diff workflow

`tools/kdiff` is the reason the table above is actionable. Given two
kernelcaches it reports the byte ranges that changed, with symbol attribution
where a symbol exists:

```
make tools
build/kdiff 27.0.1.kc 27.2.kc --top 40
```

Blocks are 16 bytes, anchored on identical 64-byte runs, so insertions and
size changes show up as `old +N -> new +M` rather than desynchronising the
whole image. `--json` is there for scripting, `--bytes` controls the hexdump.

`make diff-test` builds a synthetic pair (three patched sites, one insertion)
and asserts the tool finds them, including the symbol at each site.

Limits, stated plainly: this is a *content* diff. It will not name a function
in a stripped kernelcache, and it cannot tell a security fix from a compiler
change. It narrows thousands of functions to a handful of ranges; reading the
disassembly is still the work.

## Open questions

1. Which build is the 16e on? This decides everything above.
2. Does the 27.0.1 kernelcache for A18 differ from A19 in the AVE kext? Extract
   from the IPSW for this device, not a generic one.
3. Is the AVE bug a linear overflow with an attacker-controlled length, or a
   fixed-offset field write? The former can reach a task pointer, the latter
   usually cannot.
4. Persistence: the Hexacon chain survived reboot on 27.0.1. On a rootful
   layout that means either a patched boot component or a trust-cache +
   launchd combination that survives SSV. `rootfs/persist.c` models the
   launchd half; the boot half is unknown and not public.
