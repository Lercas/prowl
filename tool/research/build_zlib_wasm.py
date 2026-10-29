"""Build the pinned compressor module using a verified WASI SDK and zlib source archive."""
import argparse
import hashlib
import subprocess
import tarfile
import tempfile
from pathlib import Path

ZLIB_SHA256 = "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"
SDK_SHA256 = "2c2ed99296857e60fd14c3f40fe226231f296409502491094704089c31a16740"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk-archive", type=Path, required=True)
    ap.add_argument("--zlib-archive", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    for archive, want in ((args.sdk_archive, SDK_SHA256), (args.zlib_archive, ZLIB_SHA256)):
        if hashlib.sha256(archive.read_bytes()).hexdigest() != want:
            raise ValueError("source/toolchain checksum mismatch")
    work = Path(tempfile.mkdtemp(prefix="prowl-zlib-build-"))
    for archive in (args.sdk_archive, args.zlib_archive):
        with tarfile.open(archive) as tf:
            tf.extractall(work, filter="data")
    sdk = work / "wasi-sdk-30.0-arm64-macos"
    source = work / "zlib-1.3.2"
    wrapper = Path(__file__).with_name("zlib_length.c")
    sources = [source / (name + ".c") for name in ("compress", "deflate", "trees", "adler32", "crc32", "zutil")]
    # The WASM name section embeds the output basename, so pin it too.
    module = work / "zlib_length.wasm"
    subprocess.run([str(sdk / "bin/clang"), "-O2", "-DNDEBUG", "-I", str(source),
        "-nostartfiles", "-Wl,--no-entry", "-Wl,--export=input_ptr", "-Wl,--export=input_limit",
        "-Wl,--export=compressed_len", "-Wl,--initial-memory=16777216", "-Wl,--max-memory=16777216",
        "-o", str(module), str(wrapper), *map(str, sources)], check=True)
    with args.output.open("xb") as output:
        output.write(module.read_bytes())
    print("module sha256:", hashlib.sha256(args.output.read_bytes()).hexdigest())
    print("Build inputs retained for inspection:", work)


if __name__ == "__main__":
    main()
