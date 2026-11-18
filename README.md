# Melatonin

[![ci](https://github.com/mkz-lena/melatonin/actions/workflows/ci.yml/badge.svg)](https://github.com/mkz-lena/melatonin/actions/workflows/ci.yml)

Rootful iOS 27 (A18) jailbreak pipeline, plus a Linux host simulator so the
whole chain can be built and exercised without a device.

Named the obvious way: Dopamine had the slot, Melatonin takes the night shift.
It is the thing your phone needs to go under.

**status.** everything above the kernel primitive is written and verified on a
Linux host simulator: offset probe, 16K page-table walk, PAC strip/canon/rebind,
cred adoption, sandbox drop, task-port takeover, SSV snapshot switch, rootfs
remount, AMFI/CS patches, trust cache, app install, Sileo bootstrap, launchd
persistence and a UIKit front end.

what is **not** here is a kernel exploit. `mela_boot_provider()` is a weak stub
in `krw/leak.c`, so on a real phone the pipeline stops at the `primitive` stage
by design. see [Kernel Access](https://github.com/mkz-lena/melatonin/wiki/Kernel-Access).

**target.** iPhone 16e (`iPhone17,5`, A18), iOS 27.0 beta 3 (`24A5380h`).
the A18 predates MIE/EMTE, which starts at A19, so a chain for this device does
not have to defeat pointer tag checks. see
[Target Device](https://github.com/mkz-lena/melatonin/wiki/Target-Device) and
[Research](https://github.com/mkz-lena/melatonin/wiki/Research).

## Layout

```
melatonin.h     shared context, kernel r/w backends, proc/task API
offsets.h       offset table (kbase offsets + struct field offsets)
krw/            kbase, pac, virt page-table walk, providers, proc/task/sandbox,
                 amfi + code-sign patches, exploit registry, trust cache,
                 sha1/sha256, cdhash, instruction patches, image provider
rootfs/         snapshot select, remount, Mach-O re-sign walk, launchd job,
                 app install (trollstore-lite)
loader/         run.c (shared pipeline), main.m (iOS entry), selftest
sim/            Linux simulator: phys RAM, 16K page tables, fake kernel objects
app/            Swift-free UIKit front end (Melatonin.app)
bootstrap/      install.sh, post-remount.sh, sileo.sh, app-install.sh
tools/          koff, kdiff, pull_kc, device.sh, mkfixture, mkdiffpair, aa_model
docs/           HARDWARE.md, RESEARCH.md, TARGETS.md, DEVICE.md
wiki/           the same notes, ready to push to the GitHub wiki
```

## Quickstart

```sh
make sim        # builds build/melatonin-sim
make run        # runs the full pipeline against the simulator
make test       # same, non-zero on failure
make help       # all targets
```

macOS / device build:

```sh
make ios        # build/melatonind (arm64e), then ldid -S build/melatonind
make app        # build/Melatonin.app
```

## Docs

The long-form notes live in `docs/` and in the
[wiki](https://github.com/mkz-lena/melatonin/wiki):

- [Building](https://github.com/mkz-lena/melatonin/wiki/Building) — Linux, macOS,
  device build, tests, image replay, koff, kdiff, pull_kc
- [Architecture](https://github.com/mkz-lena/melatonin/wiki/Architecture) — module
  map, pipeline stages, root path, offset rebuild, trust cache, app install
- [Kernel Access](https://github.com/mkz-lena/melatonin/wiki/Kernel-Access) — the
  one function that has to be filled in
- [Tools](https://github.com/mkz-lena/melatonin/wiki/Tools) — koff, kdiff, pull_kc,
  device.sh
- [Target Device](https://github.com/mkz-lena/melatonin/wiki/Target-Device) — the
  phone and its build
- [Research](https://github.com/mkz-lena/melatonin/wiki/Research) — CVE map,
  Hexacon, why A18 matters

## Kernel access contract

`krw/leak.c` holds `mela_boot_provider()`, a weak stub. A real provider fills
`mela_phys_ops` (physical read/write, `ttbr1`, `phys_base`) and calls
`mela_phys_register()`; it also sets `g_mela.kbase` / `g_mela.kslide`. Everything
above that — VA translation, offsets probe, cred adoption, sandbox, task port,
snapshot, remount — is already wired. The sim registers its own provider through
the same call, which is why the host build runs end to end.

## Status and limits

Everything above the primitive is implemented and verified on the host,
including the offline image replay, trust cache and bundle install. No
memory-corruption primitive is shipped, described or implied here: without a
strong provider (see `docs/HARDWARE.md`) the device path stops at the
`primitive` stage, which is the intended failure mode.

`docs/RESEARCH.md` maps the public writeups onto this tree: CVE-2026-86950
(CoreGraphics glyph rasterizer), the iOS 27.2 Endpoint Security KEXT, KernelKit,
and the Hexacon 2026 disclosure. `make aa-model` reproduces the rasterizer bbox
arithmetic as a host-side regression check.

`docs/TARGETS.md` is the current map of the missing piece, including why the
16e's A18 does not need an MIE bypass: MIE/EMTE starts at A19.

`docs/DEVICE.md` records the actual target: `iPhone17,5`, iOS 27.0 beta 3
(`24A5380h`), what that build predates, and the one-way signing situation.

## License

MIT.
