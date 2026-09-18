#!/usr/bin/env python3
"""Build the minimal ARM64 Android ET_DYN used by --debug-inject so-empty."""

import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path


def find_clang(ndk: Path) -> Path:
    toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    matches = sorted(toolchain.glob("aarch64-linux-android*-clang"))
    matches = [p for p in matches if "++" not in p.name]
    if not matches:
        raise SystemExit(f"ARM64 clang not found under {toolchain}")
    return matches[-1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk", required=True)
    parser.add_argument("--api", default="33")
    parser.add_argument("--src", default=str(Path(__file__).with_name("empty_so.c")))
    parser.add_argument("--output", default=str(Path(__file__).with_name("build") / "empty.so"))
    return parser.parse_args()


def elf_ok(path: Path) -> None:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise SystemExit(f"{path} is not ELF")
    ei_class, _, _, _, _ = struct.unpack_from("BBBBB", data, 4)
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if ei_class != 2 or e_machine != 183 or e_type != 3:
        raise SystemExit(
            f"{path} is not ELF64/AArch64/ET_DYN (class={ei_class} machine={e_machine} type={e_type})"
        )


def main() -> None:
    args = parse_args()
    ndk = Path(args.ndk)
    clang = find_clang(ndk)
    src = Path(args.src)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(clang),
        f"--target=aarch64-linux-android{args.api}",
        "-shared",
        "-nostdlib",
        "-Wl,-soname,empty.so",
        "-o",
        str(out),
        str(src),
    ]
    print(" ".join(cmd))
    subprocess.check_call(cmd)
    elf_ok(out)
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
