# PaxtonSniffer V1

A passive Paxton / Hitag2 sniffer for Flipper Zero. It listens to an existing
reader-to-badge exchange and offers an EM4100 `.rfid` export after confirming
the two required data pages.

**Requires the included custom Unleashed 093 firmware. Stock Unleashed 093
and official Flipper firmware do not provide the required ADC DMA API.**

Use only with credentials and access-control systems you own or are authorized
to test. Capture logs and exported files contain credential information;
do not publish them.

## Download And Install

The ready-to-use files are already in this repository:

| File | Purpose |
| --- | --- |
| [`PaxtonSniffer.fap`](PaxtonSniffer.fap) | Application V1.0 for Flipper Zero, target F7 |
| [`firmware/flipper-z-f7-update-paxton-sniffer-v1.tgz`](firmware/flipper-z-f7-update-paxton-sniffer-v1.tgz) | Custom Unleashed 093 firmware, API 88.11 |
| [`firmware/modified_files/`](firmware/modified_files/) | All three modified firmware files |
| [`firmware/unleashed-093-paxton-sniffer.patch`](firmware/unleashed-093-paxton-sniffer.patch) | Patch against the exact upstream release |

1. Back up your Flipper settings and SD card before changing firmware.
2. Install the included `.tgz` as a local firmware update with qFlipper. An
   alternative is to extract it into the SD card's `update` directory and run
   `f7-update-u093-active/update.fuf` from the Flipper file browser.
3. Put `PaxtonSniffer.fap` in the SD card's `apps/RFID` directory.
4. Launch **Apps > RFID > Paxton Sniffer V1**.

No soldering, external antenna or other hardware modification is required.
The archive retains the internal name `f7-update-u093-active` from the existing
custom firmware build. The sniffer itself does not generate an RF field.

## Capture A Credential

1. Place the Flipper near the reader's LF antenna, then present one badge to
   the reader. The reader must perform the normal Paxton exchange.
2. Keep **the same single badge** in use for the whole capture. Repeat the
   presentation as necessary, allowing the reader to restart the exchange.
3. Wait for both E0 and E8 to have at least two matching accepted reads.
4. Acquisition stops automatically and a **Save EM4100?** dialog appears.
5. Choose **Save** to create `lfrfid/Paxton_<number>.rfid`. Existing files are
   not overwritten. The application then exits. **Cancel** exits without export.

Press **Back** to stop a capture without waiting for success. Diagnostic logs
are written after acquisition to `paxton_sniffer/sniff_000.txt`, with increasing
file numbers. The application does not write logs to the SD card while sampling.

The exported file is available in the standard **125 kHz RFID** application
for EM4100 emulation. This exports the observed Paxton number; it is **not** a
full Hitag2 memory dump, Hitag2 emulator, or guaranteed replacement for every
Paxton credential and reader generation.

## Acceptance Rules

Only complete, zero-error, SOF/Manchester-locked 32-bit responses can vote.
They must also pass Paxton five-bit odd-parity and digit-format checks:

- E0: six decimal digits.
- E8: two decimal digits followed by an `F` terminator.
- At least two identical responses per page, from distinct reader commands.
- An equally supported conflicting candidate prevents acceptance.

E0 and E8 are confirmed separately. Changing badges mid-capture could mix
pages from different badges. A two-read consensus reduces false acceptance;
it is not cryptographic verification or a calibrated confidence percentage.

The receiver combines the existing live segment decoder with a per-response
MAD transition decoder. The latter treats MAD peaks as transitions, fits the
clock to the first ten transitions of the five-bit `11111` SOF, and then
decodes the payload. It does not average unrelated page windows or export
an experimental accumulator candidate.

## Limits And Validation

- An external compatible LF reader is required. This is not a standalone
  active badge reader and does not provide NFC/13.56 MHz capture.
- Coupling and placement matter. Metal-backed readers and small fobs can be
  substantially harder to capture; neither capture time nor success is guaranteed.
- If one page count stays at zero, the application deliberately refuses export.
- Do not run other ADC, LF RFID, NFC or iButton operations concurrently.
- V1.0 preserves the V20.1 development receiver. Card capture and EM4100
  emulation worked during development. The transition decoder also recovered
  both fob pages in offline replay of recorded diagnostic windows, but the
  renamed V1 binary and end-to-end fob capture still need on-device field tests.

## Build From Source

Linux/WSL prerequisites: Git, Python 3, a C compiler for host tests, and uFBT
(`python3 -m pip install --user ufbt`). Firmware build tools and submodules
are supplied by the upstream firmware build system and need network access
on first setup.

### Firmware And Custom SDK

Run from this repository's root:

```sh
PACKAGE=$(pwd)
git clone --branch unlshd-093 --recurse-submodules \
  https://github.com/DarkFlippers/unleashed-firmware.git firmware-build
cd firmware-build
test "$(git rev-parse HEAD)" = 603f90d037c7e9db81b2b25736f8cdda28ea6ba8
git apply --check "$PACKAGE/firmware/unleashed-093-paxton-sniffer.patch"
git apply "$PACKAGE/firmware/unleashed-093-paxton-sniffer.patch"
./fbt DEBUG=0 COMPACT=1 DIST_SUFFIX=u093-active \
  UPDATE_VERSION_STRING=u093-hitag2-active updater_package
```

The update and custom SDK are generated in `firmware-build/dist/f7-C/`:

```text
flipper-z-f7-update-u093-active.tgz
flipper-z-f7-sdk-u093-active.zip
```

`COMPACT=1` is intentional. The SDK archive is not duplicated in this small
repository; rebuild it from the pinned firmware sources above. The overlay
in `firmware/modified_files/` contains the same changes as the patch.

### Application

Return to the repository's root and run:

```sh
sh tools/build_fap.sh \
  "$PWD/firmware-build/dist/f7-C/flipper-z-f7-sdk-u093-active.zip"
```

This selects the custom SDK and builds `PaxtonSniffer.fap` at the repository
root. If that SDK is already active, `sh tools/build_fap.sh` is sufficient.
Set `UFBT=/path/to/ufbt` when it is not on your `PATH`.

Builds are functionally reproducible from the supplied sources; timestamps,
tool versions and build paths can change binary hashes. After intentionally
replacing a release binary, regenerate `SHA256SUMS` with
`python3 tools/release_manifest.py --write`.

### Tests And Integrity

```sh
python3 -m unittest discover -s tests -v
python3 tools/release_manifest.py
```

The self-contained host tests compile the embedded edge decoder and the
actual acceptance/parity functions. Synthetic inputs cover decoding,
malformed frames, independent confirmations, conflicts and digit conversion.
They do not require private logs, NumPy, SciPy, a Flipper, or a firmware SDK.

## Repository Layout

```text
PaxtonSniffer.fap       Ready-to-use V1.0 application
app/                   Application manifest and C sources
firmware/              Update archive, upstream pin, patch and modified files
tests/                 Self-contained synthetic host tests
tools/                 Application build and release verification helpers
LICENSE                GPLv3 text
THIRD_PARTY_NOTICES.md  Firmware provenance, licenses and technical references
SHA256SUMS             Checksums of distributed sources and artifacts
```

There are no badge captures, credential files, active-reader experiments,
toolchain caches or Git metadata in this publication package.

## License And Credits

Application sources and local firmware modifications are provided under
GPL-3.0-only; see [LICENSE](LICENSE). Upstream firmware and bundled components
retain their own notices and licenses, including the separate ST radio
firmware license. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

This is an independent community project, not affiliated with Paxton,
Flipper Devices, DarkFlippers or STMicroelectronics.
