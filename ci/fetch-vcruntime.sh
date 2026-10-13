#!/bin/bash
# Supply app/Madeira/x86_64-vcruntime/ the way tools/fetch-vcruntime.md describes:
# download Microsoft's official x64 VC++ redistributable (VS 2015-2022, v14) and
# extract the twelve DLLs byte-for-byte, Authenticode signatures intact.
# The DLLs are never committed; this runs at build time. Needs 7zz (brew install sevenzip).
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$R/app/Madeira/x86_64-vcruntime"
URL="${VCREDIST_URL:-https://aka.ms/vs/17/release/vc_redist.x64.exe}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

curl -fsSL -o "$W/vc_redist.x64.exe" "$URL"
shasum -a 256 "$W/vc_redist.x64.exe"

# The installer is a WiX bundle with its payload cabinets appended after the PE image;
# 7-Zip's carving mode (-t#) cuts them out. Cabinets hold more cabinets and files named
# by MSI file keys rather than DLL names, so unpack every nested cabinet, then identify
# the DLLs by their version info.
mkdir -p "$W/x"
7zz x -y -bso0 -bsp0 -t# "$W/vc_redist.x64.exe" -o"$W/x/0"
python3 -I - "$W/x" <<'PY2'
import os, subprocess, sys
done = set()
for _ in range(4):
    todo = []
    for root, _, files in os.walk(sys.argv[1]):
        for fn in files:
            p = os.path.join(root, fn)
            if p not in done:
                with open(p, "rb") as f:
                    if f.read(4) == b"MSCF": todo.append(p)
    if not todo: break
    for p in todo:
        done.add(p)
        subprocess.run(["7zz", "x", "-y", "-bso0", "-bsp0", p, "-o" + p + ".d"], check=True)
print(f"unpacked {len(done)} cabinets")
PY2

mkdir -p "$OUT"
python3 -I - "$W/x" "$OUT" <<'PY'
import os, shutil, struct, sys
src, out = sys.argv[1], sys.argv[2]
want = {"concrt140.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
        "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll", "vcamp140.dll",
        "vccorlib140.dll", "vcomp140.dll", "vcruntime140.dll", "vcruntime140_1.dll",
        "vcruntime140_threads.dll"}

def ver_string(d, key):
    k = (key + "\0").encode("utf-16-le")
    i = d.find(k)
    if i < 0: return None
    i += len(k)
    while i % 4: i += 1          # VS_VERSIONINFO values are 32-bit aligned
    j = i
    while j + 1 < len(d) and d[j:j+2] != b"\0\0": j += 2
    return d[i:j].decode("utf-16-le", "replace")

def pe_info(d):
    if d[:2] != b"MZ": return None
    pe = struct.unpack_from("<I", d, 0x3c)[0]
    if d[pe:pe+4] != b"PE\0\0": return None
    machine = struct.unpack_from("<H", d, pe + 4)[0]
    off, size = struct.unpack_from("<II", d, pe + 24 + 112 + 4*8)  # PE32+ security dir
    return machine, bool(size and off + size <= len(d))

got = {}
for root, _, files in os.walk(src):
    for fn in files:
        p = os.path.join(root, fn)
        if "arm64" in fn.lower(): continue   # the ARM64 package also carries x64-format DLLs
        d = open(p, "rb").read()
        info = pe_info(d)
        if not info or info[0] != 0x8664: continue          # x64 only
        name = (ver_string(d, "OriginalFilename") or ver_string(d, "InternalName") or fn).strip().lower()
        if name in want and name not in got:
            got[name] = (p, info[1], ver_string(d, "FileVersion"))

missing = sorted(want - set(got))
for name in sorted(got):
    p, signed, ver = got[name]
    shutil.copyfile(p, os.path.join(out, name))
    print(f"{'signed  ' if signed else 'UNSIGNED'} {name:28s} {ver}")
if missing:
    sys.exit("missing from the redistributable: " + ", ".join(missing))
if not all(s for _, s, _ in got.values()):
    sys.exit("a DLL lost its Authenticode signature")
PY
ls -l "$OUT"
