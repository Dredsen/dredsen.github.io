*Author: [Dredsen](https://dredsen.github.io/)*

---

## Background

This is my first proper driver write-up, so a quick scene-setter before the technical bits.

**LOLDrivers** ("Living Off the Land Drivers") is a community-maintained catalogue of legitimately signed Windows kernel drivers that contain exploitable vulnerabilities. The idea behind **BYOVD** (Bring Your Own Vulnerable Driver) attacks is simple: load one of these signed drivers yourself, abuse its exposed kernel primitives, and walk away with capabilities that would otherwise require an unsigned driver - bypassing Driver Signature Enforcement entirely, since the driver is already signed by a real vendor.

The driver here is `FADA64.sys` - the **Broadcom Frame Access Driver**, a 2003-era NDIS protocol driver that shipped inside HP Smart Update Firmware DVD 9.30.

---

## File Metadata

| Field | Value |
|---|---|
| Filename | `FADA64.sys` |
| Original Name | `FAD.SYS` |
| MD5 | `ce9692c1cc7a575f71a899932d895603` |
| SHA1 | `9d75631fec6c8296d70201b5e72c982d5a661ab6` |
| SHA256 | `3e9b3937a792007d9d959b0749c2a61cf62fd56b12d2bf0857d761f89fa7e112` |
| Size | 21,344 bytes |
| Architecture | x64 |
| Compiled | 2003-04-24 |
| Company | Broadcom Corporation |
| Description | Frame Access Driver |
| Source | HP Smart Update Firmware DVD 9.30 - `hp\swpackages\cp013583.exe` |

---

## Certificate

| Field | Value |
|---|---|
| Subject | `CN=Broadcom Corporation, OU=Engineering Software` |
| Issuer | VeriSign Class 3 Code Signing 2004 CA |
| Thumbprint | `9C3FBCEB8F2A6CAC510DE477E2F65A38DD760BB9` |
| Serial | `3232677944AFAE8837C58AF50DD11A8A` |
| Valid | 2006-08-24 → 2009-10-23 (expired) |
| Signature Type | Catalog signed - `cpqteam.cat` / `cpqtmmp.cat` |
| Status | Expired - WHQL-era, accepted with DSE bypass or on older OS |

The driver is **catalog signed** rather than embedded-signed, meaning the signature lives in a separate `.cat` file rather than the driver PE itself. Both `.cat` files are included in the original HP package.

---

## Vulnerability Summary

The core vulnerability is an **arbitrary physical memory read primitive**.

The driver creates a device `\\.\FAD` with a **NULL DACL** - meaning any user on the system can open a handle to it without any privilege check. Through IOCTL `0x223EF4`, an unprivileged caller can supply an arbitrary physical address and a byte count. The driver maps that physical address into kernel virtual address space using `MmMapIoSpace` and copies the contents back to the caller's output buffer via `RtlMoveMemory`.

No `RequestorMode` check. No validation of the supplied physical address. No access control beyond the ability to open the device - which anyone can do.

**What this gives an attacker:** the ability to read arbitrary physical memory from user mode. Practically useful for kernel ASLR bypass (read known physical offsets to locate kernel structures), memory enumeration, or credential hunting without touching `LSASS` at the virtual-address level.

**What this does *not* give:** an arbitrary write. The write path was fully traced and ruled out - more on that below.

---

## Device Setup

The driver's `DriverEntry` at `0x17000` creates the device with no security descriptor (7-parameter `IoCreateDevice` call, `NULL` for the SD argument) and sets `DO_BUFFERED_IO`:

```c
// DriverEntry @ 0x17000
IoCreateDevice(DriverObject, 0x38u, L"\\Device\\FAD", 0x22u, 0, 0, &DeviceObject);
DeviceObject->Flags |= 0x10u;  // DO_BUFFERED_IO
IoCreateSymbolicLink(L"\\DosDevices\\FAD", L"\\Device\\FAD");
```

| Field | Value |
|---|---|
| Device Name | `\Device\FAD` |
| Symlink | `\DosDevices\FAD` → `\\.\FAD` |
| Device Type | `0x22` (`FILE_DEVICE_UNKNOWN`) |
| DevExt Size | `0x38` |
| Exclusive | No |
| `DO_BUFFERED_IO` | Yes (`Flags |= 0x10`) |
| Security Descriptor | **NULL** (world-accessible) |

`DO_BUFFERED_IO` means the I/O manager handles buffer copying between user and kernel - the driver works with a kernel-mode copy of the user's buffer rather than directly with the user pointer. This is relevant when sizing the input/output struct.

---

## IOCTL Surface

The dispatch handler lives at `sub_12750` (registered as `MajorFunction[14]`).

| IOCTL Code | Handler | Description |
|---|---|---|
| `0x223EE4` | `sub_11370` | Open NDIS adapter by name (string from user buffer) |
| `0x223EF4` | `sub_12640` | **Physical memory read** - `MmMapIoSpace` + `RtlMoveMemory` |
| `0x223EB4` | inline | Read 16-byte stats from per-open context |
| `0x223EB8` | inline | Zero internal counters |
| `0x223EE8` | inline | `NdisRequest` to open adapter |
| `0x223EEC` | inline | Set config word |

All codes use `METHOD_BUFFERED` (bits 1–0 = `0`). There is **no `RequestorMode` check anywhere in the dispatch handler**.

---

## The Vulnerable IOCTL - `0x223EF4`

`sub_12640` is the physical memory read handler. The input buffer layout is simple: 8 bytes of physical address followed by 4 bytes of size. The driver iterates in 4KB pages, mapping each physical page into kernel VA space with `MmMapIoSpace(MmNonCached)`, copying its contents into the output buffer, then unmapping:

```c
// Input/output buffer layout (METHOD_BUFFERED, minimum size 0x10):
// [+0x00] PHYSICAL_ADDRESS PhysAddr  - physical address to read (user-controlled)
// [+0x08] UINT32           Size      - byte count to read (user-controlled)

__int64 sub_12640(__int64 a1, PHYSICAL_ADDRESS *a2, unsigned int InputLen,
                  unsigned int OutputLen, _DWORD *BytesOut)
{
    PHYSICAL_ADDRESS i = *a2;           // physical address - straight from user buffer
    UINT32 remaining  = a2[1].LowPart; // size - straight from user buffer

    for (; remaining > 0x1000; remaining -= 0x1000) {
        PVOID kva = MmMapIoSpace(i, 0x1000, MmNonCached);
        RtlMoveMemory(a2, kva, 0x1000);   // copy physical → output buffer
        MmUnmapIoSpace(kva, 0x1000);
        a2 += 512;      // advance output pointer 0x1000 bytes
        i.QuadPart += 0x1000;
    }
    if (remaining) {
        PVOID kva = MmMapIoSpace(i, remaining, MmNonCached);
        RtlMoveMemory(a2, kva, remaining);
        MmUnmapIoSpace(kva, remaining);
    }
}
```

The driver does validate that `InputLen >= 0x10` before entering `sub_12640`, so you need at least 16 bytes in your input buffer. Otherwise: no bounds checking, no address validation, no privilege check.

---

## Exploit Chain

```
1. OpenFile  \\.\FAD   (no credentials required - NULL DACL, any user)

2. Build input struct:
      PHYSICAL_ADDRESS phys = TARGET_PA;   // e.g. 0x0 (IVT), 0x400 (BDA), or wherever
      UINT32           size = 0x1000;      // up to a full page per call

3. DeviceIoControl(
       hFAD,
       0x223EF4,
       &struct, sizeof(struct),    // input buffer
       &struct, sizeof(struct),    // output buffer (same, BUFFERED)
       &bytes,
       NULL
   )

4. struct now contains bytes read from physical address TARGET_PA
```

Interesting targets at known physical offsets (no ASLR at the physical layer):

- `0x0` - Interrupt Vector Table (real-mode era, but still mapped)
- `0x400` - BIOS Data Area
- `0x1000` and up - early physical RAM, often contains kernel image remnants post-boot

For a kernel ASLR bypass: read physical memory to locate the kernel image, extract the base, then pivot to virtual-address operations via a second primitive.

---

## Ruling Out a Write Primitive

Before finalising the assessment I traced every write-capable import to its call site to confirm there is no write path back to physical or kernel memory.

**`MmMapLockedPagesSpecifyCache`** (`sub_11CD0`): maps a user-supplied MDL, then calls `RtlCopyMemory(mapped_va, ndis_packet_buffer, length)`. Data flows **from the network into the user's own buffer** - this is the packet receive path. No user data is written to any kernel or physical destination.

**`MmMapIoSpace`** (`sub_12640`): maps the user-supplied physical address, then `RtlMoveMemory(output_buffer, kva, size)`. Copy direction is **physical → output buffer**, read-only. No reverse path.

**`NdisRequest`** (IOCTL `0x223EE8` path): issues NDIS OID SET requests to the NIC. Writes only to **the network adapter's own hardware registers** via the NDIS miniport - not to kernel memory or physical memory outside the NIC. OID and data are user-supplied but constrained to what the NIC's miniport accepts.

**Conclusion:** every `RtlMoveMemory` / `RtlCopyMemory` call site copies either physical → output buffer or network packet → user MDL. **No arbitrary write primitive exists in this driver.**

---

## Impact

| Property | Assessment |
|---|---|
| Primitive | Arbitrary physical memory **read** |
| Privilege required | **User** (any logged-in user, NULL DACL) |
| Write primitive | None |
| DSE bypass required | No - driver is legitimately signed (expired cert, but accepted on older OS or with catalog tricks) |
| CVE | None assigned |
| MITRE ATT&CK | T1068 - Exploitation for Privilege Escalation |
| Practical use | Kernel ASLR bypass, physical memory enumeration, credential search |

