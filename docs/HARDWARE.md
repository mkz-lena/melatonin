# Hardware bring-up

The pipeline above the kernel primitive is complete and exercised on the host.
One piece is deliberately absent: a kernel read/write primitive for A18 on
iOS 27. Nothing in this tree contains or claims to contain one.

This document is the contract that piece has to satisfy, plus the checklist for
turning a primitive into a booting rootful setup.

## What works without a primitive

- 16K 4-level translation walk, tested against real page tables in the sim.
- Struct offset autoprobe and dry-run report.
- Cred adoption, sandbox removal, task-port takeover, SSV snapshot select,
  rootfs remount, AMFI/CS patches, amfid cache flush, launchd job.
- cdhash computation, trust cache read/inject, bundle install.
- Offline kernel image format for replaying a dump.

## Provider contract

`krw/leak.c` exports a weak `mela_boot_provider(mela_phys_ops *)`. Link a strong
definition to replace it. Fill:

```c
struct {
    const char *name;
    int  (*read)(uint64_t pa, void *buf, size_t len);
    int  (*write)(uint64_t pa, const void *buf, size_t len);
    uint64_t ttbr1;      /* TTBR1_EL1 of the current task */
    uint64_t phys_base;  /* physmap base, 0 if identity */
} mela_phys_ops;
```

and set `g_mela.kbase` / `g_mela.kslide` before returning 0. Reads must cover at
least the kernel text and the heap pages holding `allproc`; 8-byte granularity
is enough, arbitrary length is better.

If the primitive is virtual rather than physical (a corrupted object giving
`read64`/`write64`), register `mela_krw_ops` through `mela_krw_register()` instead;
`kread`/`kwrite` prefer that backend.

Either way the provider is reached through `krw/exploit.c`:

```c
static const mela_exploit my_exp = { "name", attach, validate };
mela_exploit_register(&my_exp);
```

`mela_primitive_init()` walks registered exploits, then the weak boot provider,
and only accepts one whose canary read succeeds (a kernel pointer at
`g_mela.kbase` inside `[MELA_KERN_MIN, MELA_KERN_MAX)`).

## Offsets

1. `build/koff <kernelcache> --emit header > offsets_gen.h` for globals
   (`allproc`, `rootvnode`, `apfs_mount`, `cs_enforcement_disable`).
2. Struct fields come from `mela_offsets_autoprobe()` at runtime; verify with
   `--probe` and `MELA_FORCE_PROBE=1 --probe`.
3. Adjust the seeds in `krw/offsets.c` only for fields the probe cannot infer
   (currently the trust cache layout).
4. Check with `--report` once the primitive attaches.

The probe is intentionally structural (chain walking, cross-proc agreement,
port backreferences) so a wrong seed cannot silently pass.

## Trust cache

`krw/trust.c` assumes:

- a global at `trust_head` holding a pointer to the table,
- `count` and `entries` at fixed offsets inside it,
- fixed-size entries with a 20-byte hash and a flags word.

The simulator mirrors that shape. On a new build, verify the global name in the
kernelcache and update `trust_head`, `tc_*` in `krw/offsets.c`.

`mela_cdhash_file()` returns the CodeDirectory hash when the image is signed;
that is the value the kernel checks against the trust cache.

## Replay and validation

- `make test` runs the complete pipeline against simulated RAM.
- `make image-test` dumps that RAM, reopens it as a file and reruns everything,
  including install and trust injection.
- With a device dump in the same container format, `--image` reproduces the
  apply path offline: useful for developing offsets before a primitive is
  stable.

## Device checklist

- [ ] primitive attaches (`--report` shows a backend and a kbase in range)
- [ ] `--probe` validates seeds, or autoprobe rebuilds them
- [ ] `mela_apply()` reports ok for all stages
- [ ] `mela_selftest()` returns 0
- [ ] remount is writable, SSV bit clear
- [ ] trust cache accepted a test cdhash
- [ ] launchd job loaded and `--daemon` survives a respawn
- [ ] Sileo bootstrap script completes, `/var/jb/usr/bin/sileo` exists

## Notes on the target

iOS 27 on A18 keeps the pieces this tree already accounts for: 16K pages,
PAC on kernel pointers, SSV root snapshot, AMFI code-sign enforcement and the
trust cache. Product-specific hardening (PPL, TXM, KTRR) lives below the
primitive, not above it, so the post-exploitation path does not change once a
primitive exists — but the primitive itself must survive those protections.

Keep this on hardware you own, and expect offsets, symbol names and struct
layouts to differ per build. The probe and the dry-run report exist so those
differences surface as failures, not silent corruption.
