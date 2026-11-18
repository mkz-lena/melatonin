# Melatonin

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
by design. see [Kernel Access](Kernel-Access).

**target.** iPhone 16e (`iPhone17,5`, A18), iOS 27.0 beta 3 (`24A5380h`).
the A18 predates MIE/EMTE, which starts at A19, so a chain for this device does
not have to defeat pointer tag checks. see [Target Device](Target-Device).

## quickstart

```sh
make sim        # builds build/melatonin-sim
make run        # runs the full pipeline against the simulator
make test       # same, non-zero on failure
make help       # all targets
```

see [Building](Building) for the rest (macOS, device build, tests).

## where things live

- [Building](Building) — Linux, macOS, device build, tests, image replay
- [Architecture](Architecture) — module map, pipeline stages, root path, state
- [Kernel Access](Kernel-Access) — the one function that has to be filled in
- [Tools](Tools) — koff, kdiff, pull_kc, device.sh
- [Target Device](Target-Device) — the phone and its build
- [Research](Research) — CVE map, Hexacon, why A18 matters
- [docs/](https://github.com/mkz-lena/melatonin/tree/main/docs) — the same notes
  in the repo, versioned with the code

## license

MIT.
