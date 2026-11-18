# Target Device

## facts

| field | value |
|---|---|
| model | iPhone 16e (`iPhone17,5`) |
| board | `V59AP`, `t8140`, cpid `0x8140` |
| soc | A18, arm64e |
| ios | 27.0 |
| build | `24A5380h` |
| release | 2026-07-06 |
| battery | 291 cycles, 100% design capacity |

ecid and udid are redacted here; they are device-unique hardware identifiers.

`24A5380h` is iOS 27.0 beta 3. it is not a release build and it is not in the
ipsw.me API, which only tracks release trains. the restore image lives at

```
https://updates.cdn-apple.com/2026SpringSeed/fullrestores/140-36371/38D6F2FB-A7ED-4D3B-8261-2B56C137360B/iPhone17,5_27.0_24A5380h_Restore.ipsw
```

and `tools/pull_kc.sh 24A5380h` reproduces the kernelcache from it in one
command. that URL is not rediscoverable once lost, which is why it is in the
script rather than in this file only.

## why this build is the best case we could have

27.0 beta 3 shipped 6 july 2026. that is before 27.0 GM (`24A437`, 14 sep),
before 27.0.1 (`24A446`, 28 sep) and before 27.2 (`24B119`, 26 oct). every fix
in the 27.2 security bulletin is absent from this kernel, plus everything apple
patched silently *during* the beta cycle, which never receives a CVE at all.

and the A18 has no MIE/EMTE. memory integrity enforcement starts with A19
(iPhone 17, Air, 18). the Hexacon 2026 demonstration had to defeat pointer tag
checks on A19 Pro; a chain for this device does not. the hardest third of a
modern public chain is simply not present in the target.

## it is one-way from here

for `iPhone17,5` the only signed build is:

```
27.2.1   24B156   signed  2026-11-09
```

every older build, including this beta, is unsigned. a restore or an update
cannot be reversed without a nonce collision and a saved blobs set, and beta
builds have no blob ecosystem. treat the device as write-once until a
primitive exists.

so, in order:

1. settings → general → software update → automatic updates → off
2. beta updates → off (keep the profile if you want, but do not install)
3. do not erase, restore, or enter recovery
4. charging is fine, reboots are fine, network is fine

an expired beta profile only produces nagging. the danger is the automatic
overnight update, not the expiry.

## the sideloading situation

twelve provisioning profiles are installed, including four from one team id
(`Y7855LPY79`):

```
me.oatmealdome.DolphiniOS-njb-patreon-beta   JIT, needs a debugger
com.stik.stikdebug                            on-device debugger (DDI)
com.kdt.livecontainer                         runs unsigned app bundles
org.emexlabs.nyxian                           on-device code execution
```

this matters more than it looks. it proves that this specific device already
installs and runs development-signed apps, and that a debugger attaches to them.
that is the first mile of the Hexacon chain — their third entry point was an
ordinary custom app. we do not need a parser bug or a 1-click to get code
running inside the sandbox; we need a signing identity and a profile, both of
which this phone has already been through.

what that removes from the problem: entry, sandbox escape via app context, and
the "how do we get bytes onto the device" question. what remains is exactly one
thing — a kernel memory primitive reachable from a sandboxed process.

## what we learned from the kernelcaches

| build | AppleAVE2 size | note |
|---|---|---|
| 24A5380h (beta 3) | 0xeee78 | 978 KB |
| 24A446 (27.0.1) | 0xf0967 | 985 KB |
| 24B119 (27.2) | 0x2da2d2 | 2990 KB |

`AppleAVE2` triples in size between 27.0.1 and 27.2. that is not a bounds-check
patch, that is a feature merge, and it makes a whole-kext content diff useless
for isolating the AVEVideoEncoder fix: 418 changed regions, signal buried in
unrelated churn.

so the AVE family is still the most attractive *trigger* (unentitled app →
VideoToolbox → kernel OOB write, `NumberOfTemporalLayers`), but it is not a
clean *diff* target. ranking beats it.

the builds that did not change much are the better lead. `kdiff --kexts` ranks
every kext by how little it changed; a security fix in a stable kext is a
handful of instructions and stands out immediately.
