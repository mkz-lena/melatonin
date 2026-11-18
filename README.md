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
by design. see `docs/HARDWARE.md` for the one function that has to be filled in.

**target.** iPhone 16e (`iPhone17,5`, A18), iOS 27.0 beta 3 (`24A5380h`).
the A18 predates MIE/EMTE, which starts at A19, so a chain for this device does
not have to defeat pointer tag checks. `docs/DEVICE.md` records the device and
what its build predates; `docs/TARGETS.md` is the map of the missing piece.

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
tools/          koff (kernelcache symbol scanner), kdiff (kernelcache patch diff),
                 mkfixture, mkdiffpair, aa_model
docs/           HARDWARE.md (provider contract), RESEARCH.md (CVE notes),
                 TARGETS.md (which bugs are live on which build),
                 DEVICE.md (the actual phone and its build)
```

## Build and run on Linux

```
make sim        # builds build/melatonin-sim
make run        # builds and runs the full pipeline
make test       # same, exits non-zero on a failed assertion
make image-test # dump kernel RAM to a file and run the pipeline from it
make cli-test   # trust + install a demo bundle
./build/melatonin-sim --daemon 1   # run the repair loop (SIGTERM to stop)
```

The simulator mirrors the kernel at `0xFFFFFFF007004000` in a 256 MB RAM
buffer, builds real 4-level 16K-granule tables, and lays out `allproc`,
proc/proc_ro/ucred/label, task/itk_self/ipc_port, `rootvnode` and the APFS
mount. The pipeline runs against it through the same code that runs on device.

## Build on macOS

```
make ios        # build/melatonind (arm64e)
ldid -S build/melatonind

make app        # build/Melatonin.app (UIKit front end, auto-signed if ldid exists)
```

## Offset extraction

```
make tools
make tool-test                       # builds a fixture and checks the parser
build/koff <kernelcache>             # table
build/koff <kernelcache> --emit json
build/koff <kernelcache> --emit header > offsets_gen.h
```

Device build, straight off the cable (usbmuxd + libimobiledevice or
pymobiledevice3):

```
tools/device.sh        # version, build, whether it matches a public IPSW
tools/device.sh fw     # what Apple still signs for this model
```

Handles thin arm64e and FAT images, reads `LC_SEGMENT_64` for `__TEXT`
(kbase) and `LC_SYMTAB` for symbols. Missing symbols print as `0x0` and are
skipped in header output.

## Patch diffing

When a bulletin names a component and a build, the diff narrows it to bytes:

```
make tools
build/kdiff old.kc new.kc            # changed regions, biggest first
build/kdiff old.kc new.kc --json     # for scripting
build/kdiff old.kc new.kc --bytes 64 # longer hexdump per region
make diff-test                       # synthetic pair with 3 patches + 1 insertion
```

16-byte content blocks, anchored on identical 64-byte runs, so an insertion
shows up as `old +N -> new +M` instead of desynchronising the rest of the
image. Symbols are attributed when the image has them; a stripped kernelcache
gives addresses, which is what a disassembler wants anyway.

A whole-image diff between two releases is mostly normal development. The
useful view is per kext, ranked by how little moved, because a security fix is
a handful of instructions inside otherwise identical code:

```
build/kdiff old.kc new.kc --map old.map --map-new new.map --kexts --top 40
build/kdiff old.kc new.kc --map old.map --map-new new.map \
           --kext com.apple.driver.AppleAVE2 --bytes 48
```

`--kexts` needs the `__PRELINK_INFO` address maps, since a release kernelcache
is stripped. `tools/pull_kc.sh` produces a usable kernelcache and its map from
nothing but a build number:

```
tools/pull_kc.sh 24A5380h      # device build -> build/kcache/24A5380h.{macho,map}
tools/pull_kc.sh --list
```

It range-reads only the ~24 MB `kernelcache.release.*` member out of the 12 GB
IPSW, unwraps the `IM4P`/`bvx2` lzfse stream and runs `prelink_map.py` on the
result. Beta builds are not in the ipsw.me API, so their URLs are pinned in the
script.

`docs/TARGETS.md` explains why this is the current main line of work;
`docs/DEVICE.md` records the target device and what its build already has.

## Offset rebuild

`mela_offsets_probe()` validates seeds against the running kernel. If it fails,
`mela_offsets_autoprobe()` rebuilds the struct table from structural invariants:

Dry run, no state changed:

```
./build/melatonin-sim --probe               # uses seeds
MELA_FORCE_PROBE=1 ./build/melatonin-sim --probe   # forces the structural path
melatonind --probe                   # same on device
```

- proc chain: a pointer field that links proc to proc for several hops
- pid: distinct, sane, kernel proc reads 0
- cred: `proc_ro -> ucred`, same shape on every proc, uid 0 on kernel, others
  small and distinct, label is a kernel pointer
- task: `task -> itk_self -> ipc_port`, and `ip_port + kobject` points back at
  the same task
- comm: one offset readable as a printable name on every proc
- sandbox slot: `0` on the kernel label, a kernel pointer on a sandboxed
  label — found by comparing labels across procs

Globals (`allproc`, `rootvnode`, `apfs_mnt`, amfi slots) come from
`tools/koff` off the kernelcache. Struct fields come from the probe.

## Offline kernel image

```
make image-test                    # dump, reopen, probe, full apply
./build/melatonin-sim --dump kernel.img   # sparse: header + non-zero 16K pages
./build/melatonin-sim --image kernel.img probe
./build/melatonin-sim --image kernel.img  # full pipeline against the file
```

`image.h` lays out the container: magic, version, TTBR1, kernel base,
RAM size, load address, self proc and pid field. `krw/image.c` maps it and
registers as the physical backend, so the same translation walk, probe and
root path run against stored RAM instead of live memory. The stored self
proc pid is rebound to the loading process on open.

## Trust cache and cdhash

```
./build/melatonin-sim --trust path/to/App.app      # walk bundle, trust every Mach-O
./build/melatonin-sim --trust path/to/Binary
melatonind --trust ...
```

`krw/cdhash.c` computes the real cdhash: it finds `LC_CODE_SIGNATURE`, walks the
embedded superblob, picks `CSSLOT_CODEDIRECTORY`, and hashes the CodeDirectory
with the hash type recorded in it (SHA-1 or SHA-256), keeping 20 bytes. Unsigned
images fall back to a truncated SHA-256 of the whole file, so the tool still
works pre-sign. Hash primitives live in `krw/hash.c` and are shared by device
and host builds.

`krw/trust.c` reads the trust cache head from `trust_head`, then count/entries
from the table, and can look up, find a free slot, or inject a cdhash.

## App install (TrollStore-lite)

```
./build/melatonin-sim --install path/to/App.app
```

`rootfs/install.c` copies the bundle into `/Applications/<name>.app`, fixes
ownership and mode, signs executables with `ldid` when present, registers each
Mach-O in the trust cache, then refreshes the icon cache and restarts `installd`.
`MELA_SIM_ROOT` redirects the whole operation into the simulator root.

## Sileo bootstrap

`bootstrap/sileo.sh` builds the dpkg/apt skeleton under `/var/jb`, adds the
Sileo repo and installs it. `bootstrap/app-install.sh <App.app>` is the shell
equivalent of the C install path for already-extracted bundles.

Symptoms on device are written to a single snapshot:

```
melatonind --report
./build/melatonin-sim --report
```

It prints the attached backend, kbase/slide, TTBR1, the live offset table,
trust cache capacity, the self-test mask and the exploit that won.

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

## Kernel access contract

`krw/leak.c` holds `mela_boot_provider()`, a weak stub. A real provider fills
`mela_phys_ops` (physical read/write, `ttbr1`, `phys_base`) and calls
`mela_phys_register()`; it also sets `g_mela.kbase` / `g_mela.kslide`. Everything
above that — VA translation, offsets probe, cred adoption, sandbox, task port,
snapshot, remount — is already wired.

The sim registers its own provider through the same call, which is why the
host build runs end to end.

## State

- 16K 4-level walk: verified against the sim tables.
- Offset probe validates linkage and aborts cleanly on mismatch.
- Root path: adopt kernel creds -> sandbox off -> task port -> snapshot -> rw
  -> amfi/cs off -> amfid flush -> launchd job.
- `--daemon` mode re-checks `mela_state_ok()` and reapplies on drift; snapshot
  switch is idempotent so a second pass is a no-op.
- `mela_selftest()` re-checks creds, sandbox, task port, mount, cs flag and both
  stub patches; runs at the end of apply and on daemon start.
- `krw/patch.c` provides `b`/`bl`/`ret`/`nop` writers with range checks.
- `krw/image.c` serves a dumped RAM image through the same physical backend.
- `krw/exploit.c` keeps a provider registry and falls back to the weak boot
  provider; `mela_primitive_init()` picks the first backend whose canary read
  succeeds.
- `krw/cdhash.c` + `krw/hash.c` compute code-directory hashes; `krw/trust.c`
  reads and extends the trust cache.
- `rootfs/install.c` installs a bundle, signs it and trusts its binaries.
- `app/` is a minimal UIKit front end that calls `mela_run()`.
- Verifier asserts uid/ruid zero, sandbox cleared, port bound to kernel task,
  SSV bit clear, mount writable, cs flag set, both stub patches in place,
  launchd plist written, SHA-1/SHA-256 vectors, cdhash fallback, trust cache
  lookup/inject, and a full bundle install with trust registration.
