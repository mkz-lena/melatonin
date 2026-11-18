# Research

## Hexacon 2026

on 16 oct 2026 Calif demonstrated an untethered iOS 27.0.1 jailbreak on an
iPhone 18 Pro (A19 Pro, MIE active): survived reboot, root shell after passcode.
entry was a booby-trapped PDF via Signal (1-click), same via iMessage, and a
custom app. no tool released; "everything will be released in due time". most of
the chain fixed in 27.2 (26 oct); 27.2.1 current.

## the part that changes our plan

the demo target was A19 Pro, so it had to beat MIE. the 16e is A18, and
MIE/EMTE starts at A19. no tag checks, no tag confidentiality. we don't need
the hardest half of their chain.

and 27.2's bulletin names the kernel writes that were still live on 27.0.1,
all "an app may be able to...": CVE-2026-112507, -84495, -112696, -84494,
-112689, -112470/-468/-469, -112466 (read), -65350, -112517, -112514.

the AVE family is the concrete lead: reachable through VideoToolbox from an
ordinary app, trigger field `NumberOfTemporalLayers`, and a third-party repro
exists.

## calif's writeups

- `https://calif.io/research/apple-internals` (KernelKit): macOS 27 ships
  `/System/KernelKit/` with `Libm.kext` and `pthread.kext`, platform id 25;
  iOS 27 uses 26. the macOS pthread build carries 37 embedded Swift runtime
  symbols, ~2.4 KB of `__TEXT_EXEC`. nothing references them; on iOS the runtime
  isn't even linked in. xnu is still C/C++. no new iOS attack surface yet —
  watch it, don't chase it.
- `https://calif.io/research/rust-in-peace`: Crubit/ICU4X defensive post. no
  apple code, no ios target. one line worth keeping: the generated
  C++↔Rust bridge "still contains bugs that can cause out-of-bounds writes and
  use-after-free." memory-safe rewrites move bugs to the boundary, they don't
  delete them.

## CVE-2026-86950

CoreGraphics glyph rasterizer, fixed in 26.7.1 (extended to older devices in
27.2). `tools/aa_model.c` reproduces the bbox arithmetic: 64-byte allocation,
34,308 bytes needed. `make aa-model` is the host-side regression check.

## CoreGraphics PDF OOB writes

CVE-2026-112610 / -112611 fixed in 26.7.2 / 27.2.

## Endpoint Security KEXT

research-mode only, iOS 27.2.

## SKVLENT Bench27

`github.com/SKVLENT/iOS27-Research-Exploits`: static analysis + on-device bench,
explicitly no exploit. useful methodology reference and CVE cross-index.

## see also

- `docs/TARGETS.md` — the full CVE target table and A18 mitigation list
- `docs/RESEARCH.md` — the same notes in the repo
- `tools/aa_model.c` — `make aa-model`
- `tools/kdiff.c` — `make diff-test`
