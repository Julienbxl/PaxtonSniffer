#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate or verify the standalone publication's checksums and firmware patch."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent.parent


def release_files():
    paths = [ROOT / name for name in ("PaxtonSniffer.fap", "README.md", "LICENSE",
                                     "CHANGELOG.md", "THIRD_PARTY_NOTICES.md",
                                     ".gitignore", ".gitattributes")]
    for directory in ("app", "firmware", "tests", "tools"):
        for path in (ROOT / directory).rglob("*"):
            relative = path.relative_to(ROOT / directory)
            if not path.is_file() or any(part in {"dist", ".ufbt", ".vscode", "__pycache__"}
                                         for part in relative.parts):
                continue
            if path.suffix in {".pyc", ".pyo"}:
                continue
            paths.append(path)
    return sorted(paths)


def checksums():
    return "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                   f"{path.relative_to(ROOT).as_posix()}\n" for path in release_files())


def verify_patch(upstream):
    patch = ROOT / "firmware/unleashed-093-paxton-sniffer.patch"
    overlay = ROOT / "firmware/modified_files"
    with tempfile.TemporaryDirectory(prefix="paxton-patch-") as directory:
        temporary = Path(directory)
        for name in upstream["modified_files"]:
            destination = temporary / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((overlay / name).read_bytes())
        # A complete reverse/forward round trip checks the exact context, not
        # only a textual list of file names in the patch.
        subprocess.run(["git", "apply", "--no-index", "--reverse", str(patch)],
                       cwd=temporary, check=True)
        subprocess.run(["git", "apply", "--no-index", str(patch)],
                       cwd=temporary, check=True)
        for name in upstream["modified_files"]:
            if (temporary / name).read_bytes() != (overlay / name).read_bytes():
                raise ValueError(f"patch/overlay mismatch: {name}")


def verify_artifacts():
    fap = (ROOT / "PaxtonSniffer.fap").read_bytes()
    if fap[:4] != b"\x7fELF" or len(fap) < 52 or fap[4:6] != b"\x01\x01":
        raise ValueError("application is not a little-endian 32-bit ELF/FAP")
    if int.from_bytes(fap[18:20], "little") != 40:
        raise ValueError("application does not target ARM")
    section_offset = struct.unpack_from("<I", fap, 32)[0]
    section_size, section_count, string_index = struct.unpack_from("<HHH", fap, 46)
    if (section_size != 40 or string_index >= section_count or
            section_offset + section_size * section_count > len(fap)):
        raise ValueError("invalid ELF section table")

    def section(index):
        return struct.unpack_from("<10I", fap, section_offset + section_size * index)

    def contents(header):
        offset, size = header[4:6]
        if offset + size > len(fap):
            raise ValueError("invalid ELF section bounds")
        return fap[offset:offset + size]

    strings = contents(section(string_index))
    manifests = [contents(header) for header in map(section, range(section_count))
                 if strings[header[0]:].split(b"\0", 1)[0] == b".fapmeta"]
    if len(manifests) != 1 or len(manifests[0]) < 52:
        raise ValueError("missing FAP metadata")
    magic, revision, api_version, target, stack, app_version, name = struct.unpack_from(
        "<IIIHHI32s", manifests[0])
    if ((magic, revision, api_version, target, stack, app_version) !=
            (0x52474448, 1, (88 << 16) | 11, 7, 8192, 1 << 16) or
            name.split(b"\0", 1)[0] != b"Paxton Sniffer V1"):
        raise ValueError("FAP metadata is not Paxton Sniffer V1.0 / F7 / API 88.11")
    with tarfile.open(ROOT / "firmware/flipper-z-f7-update-paxton-sniffer-v1.tgz", "r:gz") as archive:
        required = {"update.fuf", "firmware.dfu", "radio.bin", "updater.bin", "resources.ths"}
        names = {Path(item.name).name for item in archive.getmembers() if item.isfile()}
        if not required <= names:
            raise ValueError(f"incomplete firmware archive: {required - names}")
        for item in archive.getmembers():
            if item.name.startswith("/") or ".." in Path(item.name).parts:
                raise ValueError("unsafe firmware archive path")
    upstream = json.loads((ROOT / "firmware/upstream.json").read_text())
    api = ROOT / "firmware/modified_files/targets/f7/api_symbols.csv"
    if f"Version,+,{upstream['api']},," not in api.read_text().splitlines():
        raise ValueError("firmware API pin does not match exported symbols")
    verify_patch(upstream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate SHA256SUMS")
    args = parser.parse_args()
    verify_artifacts()
    expected = checksums()
    manifest = ROOT / "SHA256SUMS"
    if args.write:
        manifest.write_text(expected)
        print(f"Wrote SHA256SUMS for {len(expected.splitlines())} files.")
    elif not manifest.exists() or manifest.read_text() != expected:
        raise SystemExit("Release checksums differ. Review changes before using --write.")
    else:
        print(f"Verified {len(expected.splitlines())} files, FAP V1.0 / API 88.11, firmware archive and patch overlay.")


if __name__ == "__main__":
    main()
