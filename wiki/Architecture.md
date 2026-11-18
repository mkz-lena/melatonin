# Architecture

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

## Pipeline stages

`mela_run()` (shared between `melatonind` and the simulator) runs:

1. attach a primitive (`mela_primitive_init`, from the exploit registry)
2. resolve offsets (`mela_offsets_probe`, or `mela_offsets_autoprobe`)
3. become root (cred adoption, sandbox drop)
4. take the task port
5. switch the SSV snapshot, remount rootfs read-write
6. patch AMFI / code signing, flush amfid's cache
7. persist a launchd job
8. `mela_selftest()`

`--daemon` mode re-checks `mela_state_ok()` and reapplies on drift; the snapshot
switch is idempotent so a second pass is a no-op.

## Root path

- `krw/leak.c` holds `mela_boot_provider()`, a weak stub. A real provider fills
  `mela_phys_ops` (physical read/write, `ttbr1`, `phys_base`) and calls
  `mela_phys_register()`; it also sets `g_mela.kbase` / `g_mela.kslide`.
  Everything above that — VA translation, offsets probe, cred adoption, sandbox,
  task port, snapshot, remount — is already wired.
- `krw/exploit.c` keeps a provider registry and falls back to the weak boot
  provider; `mela_primitive_init()` picks the first backend whose canary read
  succeeds.
- `krw/probe.c` validates linkage and aborts cleanly on mismatch.
- `krw/patch.c` provides `b`/`bl`/`ret`/`nop` writers with range checks.

## Offset rebuild

`mela_offsets_probe()` validates seeds against the running kernel. If it fails,
`mela_offsets_autoprobe()` rebuilds the struct table from structural invariants:

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

## 16K 4-level walk

`krw/virt.c` walks L0-L3 with a 16K granule and 42-bit VA, strips PAC bits,
canonicalises, and rebinds. Verified against the sim tables.

## Trust cache and cdhash

`krw/cdhash.c` computes the real cdhash: it finds `LC_CODE_SIGNATURE`, walks the
embedded superblob, picks `CSSLOT_CODEDIRECTORY`, and hashes the CodeDirectory
with the hash type recorded in it (SHA-1 or SHA-256), keeping 20 bytes. Unsigned
images fall back to a truncated SHA-256 of the whole file, so the tool still
works pre-sign. Hash primitives live in `krw/hash.c` and are shared by device
and host builds.

`krw/trust.c` reads the trust cache head from `trust_head`, then count/entries
from the table, and can look up, find a free slot, or inject a cdhash.

CLI:

```sh
./build/melatonin-sim --trust path/to/App.app      # walk bundle, trust every Mach-O
./build/melatonin-sim --trust path/to/Binary
melatonind --trust ...
```

## App install (TrollStore-lite)

```sh
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

## Reporting

Symptoms on device are written to a single snapshot:

```sh
melatonind --report
./build/melatonin-sim --report
```

It prints the attached backend, kbase/slide, TTBR1, the live offset table,
trust cache capacity, the self-test mask and the exploit that won.

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
