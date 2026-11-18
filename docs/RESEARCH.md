# Research notes

Five Calif posts, the Hexacon disclosure, and what each one changes here.

## The thing that matters: Hexacon 2026

On 16 October 2026 Calif demonstrated an **untethered iOS 27.0.1 jailbreak on
an iPhone 18 Pro** (A19 Pro, so with MIE active). It survived a reboot and came
back with a root shell after the passcode. Entry points shown: a booby-trapped
PDF delivered through Signal (1-click), the same through iMessage, and a custom
app. No tool was released. Most of the chain was fixed in iOS 27.2 on 26
October; 27.2.1 is current.

What that establishes, and what it does not:

- It is possible on the shipping OS, with the newest mitigations on.
- The entry is a PDF in a messaging app — the same class as the glyph bug.
- The bugs are named in Apple's 27.2 bulletin but their triggers are not public.
- Nothing was released. There is no code to use.

For this project the important consequence is different. The demo target had
MIE. **The iPhone 16e is A18, and MIE/EMTE starts at A19.** No tag checks, no
tag confidentiality on this hardware. Whatever chain we build does not have to
defeat the thing the Hexacon chain had to defeat.

## CVE-2026-86950 — CoreGraphics glyph rasterizer

**Fixed in iOS 26.7.1**, extended to older devices in the 27.2 cycle. Reported
by Meta Product Security, exploited in the wild against specific targets.

Root cause, in order:

1. `aa_double_to_fixed()` scales a device coordinate by 4096 and casts to
   `int32_t`. Out-of-range doubles are undefined behaviour.
2. Clang compiled `aa_moveto` with a saturating 32-bit `FCVTZS`, but
   `aa_lineto` with a 64-bit `FCVTZS` followed by `XTN` (low 32 bits). The two
   paths disagree once coordinates exceed the int32 range.
3. `aa_add_edges` computes `dx = new_x - cur_x` in `int32_t`. With one endpoint
   saturated and the other truncated, `dx` wraps, the wrong endpoint is
   compared, and neither branch widens the bbox.
4. `aa_cache_render` sizes its coverage buffer from that bbox:
   `width_px = (max_x - min_x) / 4096`, then
   `malloc`/`alloca(4 * (width_px + 16))`.
5. Edge drawing writes alpha values at columns derived from the real edge
   coordinates, past the end of the buffer.

The primitive is a controlled-offset out-of-bounds **16-bit increment on two
adjacent 16-bit values**, with attacker control over allocation size and a
choice between heap and stack (`alloca` when `width_px <= 1015`). Reaching it
from a file requires a font embedded in a PDF and a path that routes glyph
rendering through `CGGlyphBitmapCreateWithPathAndDilation` (flags clear, no
device-coordinate clip rect).

`tools/aa_model.c` is an arithmetic model of steps 1–4:

```
$ make aa-model
5.2e+05   -5.2e+05   5.2e+05    alloc 64   need 34308   underallocated
model: bbox [2129920000, 2129920000], allocation 64 bytes, edges need 34308
```

That model is a regression test for the analysis, not a trigger.

### What it is not

A **userspace** bug in a rendering process. "Going from this to code execution
is another exercise entirely." It does not give kernel access. It is an
*entry*, and on 27.x the specific bug is patched — but the 27.2 bulletin shows
two more CoreGraphics PDF OOB writes (CVE-2026-112610 / -112611) that were still
live on 27.0.1. The class is alive even when this instance is not.

## Endpoint Security in the iOS 27.2 beta

`com.apple.iokit.EndpointSecuritySE` and `libEndpointSecurity.dylib` exist, and
are inert on retail hardware:

- the KEXT requires research mode or extended-research mode (SRD fusing) before
  it registers its MAC policy or publishes the IOKit service;
- all 37 allowed event types are `NOTIFY_*`; there are no `AUTH_*` types, so no
  client can block an operation;
- `watchdogd` is the only `.embeddedclient` holder and never calls
  `es_subscribe`;
- connection type 2 (`EndpointSecurityNoAuthClient`) has no entitlement check
  in `newUserClient`, only sandbox, and exposes `memoryStats`.

Post-jailbreak, a root unsandboxed process could open that type-2 client for
instrumentation. Pre-jailbreak, on retail, it is nothing.

## Apple Internals: Swift in the kernel

KernelKit is real but empty on iOS:

- macOS 27 ships `/System/KernelKit/` with `Libm.kext` and `pthread.kext` built
  against `kernelkit.macosx27.0.internal`, platform ID 25. iOS 27 uses platform
  26 and ships `pthread`/`Libm` as KernelKit-platform binaries.
- On macOS the pthread build carries 37 Embedded Swift runtime symbols
  (`swift_retain`, `swift_release`, `swift_once`, `swift_dynamicCast`, ...) —
  about 2.4 KB of `__TEXT_EXEC`.
- **No other kext references them.** On iOS the runtime is not linked in at
  all. XNU is still 1,855 C11 + 249 C++14 compile units, zero Swift.

So there is no new Swift attack surface on iOS 27 today. Worth watching: when
the first Swift kernel component lands, it will be new code with new bugs, and
it will be in the kernelcache before any source is published.

## Rust in Peace

A defensive post about replacing C++ with Rust incrementally through Crubit,
using ICU4X as the worked example. No Apple code, no iOS component, no
vulnerability of its own. It is a signal about where Apple's third-party
dependencies are heading, not a target.

One line in it is worth keeping: the generated C++↔Rust bridge "still contains
bugs that can cause out-of-bounds writes and use-after-free." Memory-safe
rewrites move bugs to the boundary; they do not delete them.

## Target matrix

Corrected for the 16e's SoC:

| build | PDF OOB | app-reachable kernel writes | MIE | notes |
| --- | --- | --- | --- | --- |
| ≤ 26.7 | 86950 live | many | no | oldest, most surface |
| 26.7.1 / 26.7.2 | 86950 closed | many | no | 26.7.2 closed 610/611 too |
| 27.0.1 | 610/611 live | 6+ (see TARGETS.md) | no on A18 | **the Hexacon build** |
| 27.2 | closed | closed | no on A18 | 163 CVEs |
| 27.2.1 | closed | closed | no on A18 | current, brotli fix |

`docs/TARGETS.md` lists the specific kernel CVEs and the diff workflow that
turns them into addresses.

## Next questions

1. What build is the 16e on? Everything above turns on this.
2. Can the AVEVideoEncoder bug be reduced to a controlled-length write? That is
   the difference between a crash and a primitive.
3. Does a 27.0.1 A18 kernelcache show the same AVE code as the A19 one? Extract
   per-device, not generic.
4. Persistence on 27.0.1 without an MIE bypass: what did the Hexacon chain
   patch, and does the same surface exist on A18?

This repository still contains no exploit code. Everything from the primitive
upward is built and tested here; the primitive itself is the open problem, and
`docs/TARGETS.md` is the current map of it.
