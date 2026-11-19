"""
Build script for the SecureFast C11 Native Core (`native/securefast_core.c`).

Automatically selects the best available C11 compiler:
  1. `python -m ziglang cc` (bundled cross-platform LLVM C compiler — zero system setup needed!)
  2. `clang`
  3. `gcc`

Outputs:
  - Windows: `securefast/native_bin/securefast_core.dll`
  - Linux:   `securefast/native_bin/libsecurefast_core.so`
  - macOS:   `securefast/native_bin/libsecurefast_core.dylib`
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NATIVE_DIR = ROOT / "native"
OUT_DIR = ROOT / "securefast" / "native_bin"
SRC_FILE = NATIVE_DIR / "securefast_core.c"
BENCH_SRC = NATIVE_DIR / "bench_c.c"


def lib_filename() -> str:
    sys_name = platform.system().lower()
    if sys_name == "windows":
        return "securefast_core.dll"
    if sys_name == "darwin":
        return "libsecurefast_core.dylib"
    return "libsecurefast_core.so"


def find_compiler() -> list[str]:
    # Prefer ziglang (reliable 64-bit LLVM C11 compiler on Windows, Linux, and macOS)
    try:
        import ziglang  # noqa: F401
        return [sys.executable, "-m", "ziglang", "cc"]
    except ImportError:
        pass

    for cc in ("clang", "gcc"):
        found = shutil.which(cc)
        if found:
            return [found]

    raise RuntimeError(
        "No C11 compiler found. Install ziglang (`pip install ziglang`) or gcc/clang."
    )


def build_shared_library(build_bench: bool = False) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_lib = OUT_DIR / lib_filename()
    cc = find_compiler()

    sys_name = platform.system().lower()
    cmd = [
        *cc,
        "-std=c11",
        "-O3",
        "-Wall",
        "-Wextra",
        "-shared",
        f"-I{NATIVE_DIR}",
        str(SRC_FILE),
        "-o",
        str(out_lib),
    ]
    if sys_name != "windows":
        cmd.extend(["-fPIC", "-lm"])

    print(f"[build_native] Compiling C11 native engine -> {out_lib.name}")
    print(f"[build_native] Command: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    print(f"[build_native] Built {out_lib} ({out_lib.stat().st_size:,} bytes)")

    if build_bench:
        bench_ext = ".exe" if sys_name == "windows" else ""
        out_bench = OUT_DIR / f"bench_c{bench_ext}"
        bench_cmd = [
            *cc,
            "-std=c11",
            "-O3",
            "-Wall",
            "-Wextra",
            f"-I{NATIVE_DIR}",
            str(SRC_FILE),
            str(BENCH_SRC),
            "-o",
            str(out_bench),
        ]
        if sys_name != "windows":
            bench_cmd.append("-lm")
        print(f"[build_native] Compiling C11 benchmark -> {out_bench.name}")
        subprocess.run(bench_cmd, check=True)

    return out_lib


if __name__ == "__main__":
    want_bench = "--bench" in sys.argv
    build_shared_library(build_bench=want_bench)
