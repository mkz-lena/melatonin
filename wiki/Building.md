# Building

## Linux (host simulator)

```sh
make sim        # builds build/melatonin-sim
make run        # builds and runs the full pipeline
make test       # same, exits non-zero on a failed assertion
make image-test # dump kernel RAM to a file and run the pipeline from it
make cli-test   # trust + install a demo bundle
./build/melatonin-sim --daemon 1   # repair loop (SIGTERM to stop)
```

The simulator mirrors the kernel at `0xFFFFFFF007004000` in a 256 MB RAM
buffer, builds real 4-level 16K-granule tables, and lays out `allproc`,
proc/proc_ro/ucred/label, task/itk_self/ipc_port, `rootvnode` and the APFS
mount. The pipeline runs against it through the same code that runs on device.

## macOS

```sh
make ios        # build/melatonind (arm64e)
ldid -S build/melatonind

make app        # build/Melatonin.app (UIKit front end, auto-signed if ldid exists)
```

## Offset extraction

```sh
make tools
make tool-test                       # builds a fixture and checks the parser
build/koff <kernelcache>             # table
build/koff <kernelcache> --emit json
build/koff <kernelcache> --emit header > offsets_gen.h
```

Handles thin arm64e and FAT images, reads `LC_SEGMENT_64` for `__TEXT`
(kbase) and `LC_SYMTAB` for symbols. Missing symbols print as `0x0` and are
skipped in header output.

Device build, straight off the cable (usbmuxd + libimobiledevice or
pymobiledevice3):

```sh
tools/device.sh        # version, build, whether it matches a public IPSW
tools/device.sh fw     # what Apple still signs for this model
```

## Patch diffing

When a bulletin names a component and a build, the diff narrows it to bytes:

```sh
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

```sh
build/kdiff old.kc new.kc --map old.map --map-new new.map --kexts --top 40
build/kdiff old.kc new.kc --map old.map --map-new new.map \
           --kext com.apple.driver.AppleAVE2 --bytes 48
```

`--kexts` needs the `__PRELINK_INFO` address maps, since a release kernelcache
is stripped. `tools/pull_kc.sh` produces a usable kernelcache and its map from
nothing but a build number:

```sh
tools/pull_kc.sh 24A5380h      # device build -> build/kcache/24A5380h.{macho,map}
tools/pull_kc.sh --list
```

It range-reads only the ~24 MB `kernelcache.release.*` member out of the 12 GB
IPSW, unwraps the `IM4P`/`bvx2` lzfse stream and runs `prelink_map.py` on the
result. Beta builds are not in the ipsw.me API, so their URLs are pinned in the
script.

## Offline kernel image

```sh
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
