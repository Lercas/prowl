"""Generate the existing binary Homebrew formula from a verified release checksum list."""

import argparse
from pathlib import Path
import re


def formula(tag: str, checksums: str) -> str:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("expected a v-prefixed release version")
    version = tag[1:]
    hashes = {}
    for line in checksums.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\s]+)", line)
        if not match or match[2] in hashes:
            raise ValueError("malformed or duplicate checksum entry")
        hashes[match[2]] = match[1]
    lines = ["class Prowl < Formula",
             '  desc "Secret scanner for code, git, images, buckets, and live apps"',
             '  homepage "https://github.com/Lercas/prowl"',
             '  license "PolyForm-Noncommercial-1.0.0"', f'  version "{version}"', ""]
    for os_name, block in (("darwin", "macos"), ("linux", "linux")):
        lines.append(f"  on_{block} do")
        for arch, arch_block in (("arm64", "arm"), ("amd64", "intel")):
            name = f"prowl_{version}_{os_name}_{arch}.tar.gz"
            if name not in hashes:
                raise ValueError(f"missing archive checksum: {name}")
            lines += [f"    on_{arch_block} do",
                      f'      url "https://github.com/Lercas/prowl/releases/download/{tag}/{name}"',
                      f'      sha256 "{hashes[name]}"', "    end"]
        lines += ["  end", ""]
    lines += ["  def install", '    bin.install "prowl"', "  end", "", "  test do",
              '    assert_match version.to_s, shell_output("#{bin}/prowl version")', "  end", "end", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generated = formula(args.tag, args.checksums.read_text())
    with args.output.open("x") as output:
        output.write(generated)


if __name__ == "__main__":
    main()
