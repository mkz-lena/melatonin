# Tools

## koff — kernelcache symbol scanner

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

## kdiff — kernelcache patch diff

When a bulletin names a component and a build, the diff narrows it to bytes:

```sh
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

`--guards` ranks regions by the shape of a bounds fix — new `cmp`, unsigned
conditional branch, `csel` — and `--match <substr>` narrows the kext list:

```sh
build/kdiff old.kc new.kc --guards --top 20 --map old.map --map-new new.map
```

Read the survivors as instructions:

```sh
tools/kdis.sh build/kcache/24A5380h.macho 0xfffffff008552a8c 512
tools/kguard.sh old.kc new.kc 0xfffffff00853917c 0xfffffff00854726c 128
```

`kdis.sh` cuts a VM range out of the fileset and disassembles it with the VM
address as base; `kguard.sh` diffs the same range across two builds with
addresses normalised.

## livecontainer — run an unsigned bundle

```sh
make app-linux                        # theos sdk, arm64, ad-hoc signed
tools/livecontainer.sh build/Melatonin-linux.app
```

LiveContainer re-signs guest apps with its own certificate, so this needs no
developer identity and no Mac. It is the on-device execution channel for
melatonin's own UI and for small probes.

## pull_kc — IPSW to kernelcache

```sh
tools/pull_kc.sh 24A5380h      # device build -> build/kcache/24A5380h.{macho,map}
tools/pull_kc.sh --list
```

It range-reads only the ~24 MB `kernelcache.release.*` member out of the 12 GB
IPSW, unwraps the `IM4P`/`bvx2` lzfse stream and runs `prelink_map.py` on the
result. Beta builds are not in the ipsw.me API, so their URLs are pinned in the
script.

## device.sh — read the build off a phone

```sh
tools/device.sh        # version, build, whether it matches a public IPSW
tools/device.sh dev    # developer-mode surface: DDI mount, DVT process table
tools/device.sh fw     # what Apple still signs for this model
```

Requires usbmuxd + libimobiledevice or pymobiledevice3. No jailbreak involved.
`dev` is the one that matters on a beta build: a mounted `/System/Developer`
means developer mode is on and DVT answers, which is an execution channel that
does not need a re-signed app.
