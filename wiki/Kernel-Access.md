# Kernel Access

`krw/leak.c` holds `mela_boot_provider()`, a weak stub. A real provider fills
`mela_phys_ops` (physical read/write, `ttbr1`, `phys_base`) and calls
`mela_phys_register()`; it also sets `g_mela.kbase` / `g_mela.kslide`. Everything
above that — VA translation, offsets probe, cred adoption, sandbox, task port,
snapshot, remount — is already wired.

The sim registers its own provider through the same call, which is why the
host build runs end to end.

## Checklist

- [ ] `mela_phys_ops.read_phys(va, len, buf)` works for kernel physical addresses
- [ ] `mela_phys_ops.write_phys(va, len, buf)` works for kernel physical addresses
- [ ] `mela_phys_ops.ttbr1` points at the kernel page table root
- [ ] `mela_phys_ops.phys_base` is the physical offset of the kernel text base
- [ ] `g_mela.kbase` inside `[MELA_KERN_MIN, MELA_KERN_MAX)`
- [ ] `g_mela.kslide` is the slide, or 0 if kbase already equals the seed
- [ ] `mela_phys_register()` called before returning 0
- [ ] `mela_primitive_init()` runs the registry and validates with a canary read
      of `g_mela.kbase`

## Bring-up on device

```sh
melatonind --probe
MELA_FORCE_PROBE=1 melatonind --probe   # forces the structural path
melatonind --report
```

## See also

- `docs/HARDWARE.md` — the full provider contract and known-good values
- `krw/exploit.c` — the registry; the first candidate that reads `g_mela.kbase`
  wins
- `krw/leak.c` — `mela_boot_provider()` and `mela_primitive_init()`
