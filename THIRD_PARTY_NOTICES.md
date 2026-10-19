# Third-Party Notices

## Firmware Provenance

The included firmware archive is an unchanged copy of the existing custom
Unleashed 093 build, renamed for this release. Its internal update directory
is `f7-update-u093-active`, its update label is `u093-hitag2-active`, and its
exported API is 88.11. The additional bounded ADC functions are retained for
compatibility; PaxtonSniffer uses the passive streaming API only.

The complete upstream project is
[DarkFlippers/unleashed-firmware](https://github.com/DarkFlippers/unleashed-firmware),
tag `unlshd-093`, commit
[`603f90d037c7e9db81b2b25736f8cdda28ea6ba8`](https://github.com/DarkFlippers/unleashed-firmware/tree/603f90d037c7e9db81b2b25736f8cdda28ea6ba8).
It in turn incorporates [Flipper Devices firmware](https://github.com/flipperdevices/flipperzero-firmware).

The complete local difference from that upstream commit is supplied as
`firmware/unleashed-093-paxton-sniffer.patch`. All three resulting files are
also supplied under `firmware/modified_files/`. `firmware/upstream.json` pins
the upstream source and build options. Clone the exact commit and its
submodules, then apply the patch as described in the README to reconstruct
the firmware source tree. There are no other local firmware source changes.

The upstream top-level GPLv3 license is reproduced in `LICENSE`. Copyright
notices and component-specific licenses in the upstream repository and its
pinned submodules remain applicable. The firmware archive is not represented
as being entirely under a single license.

The update contains an unmodified STMicroelectronics radio firmware binary.
Its upstream license is reproduced in
[`firmware/ST_RADIO_LICENSE.md`](firmware/ST_RADIO_LICENSE.md); it is not
relicensed under the application's GPL license.

## Technical References

The Paxton format and EM4100 export work build on public community research:

- [How to Flipper a Paxton, badcfe](https://badcfe.org/how-to-flipper-a-paxton/).
- [How to Paxton with RFIDler, badcfe](https://badcfe.org/how-to-paxton-with-rfidler/).
- [Nat McHugh's Paxton research](https://gist.github.com/natmchugh/18e82761dbce52fa284c87c190dc926f).
- [Proxmark3 community firmware](https://github.com/RfidResearchGroup/proxmark3),
  consulted for Hitag2 frame and timing behavior.

These references are acknowledged for technical context; they do not imply
endorsement or that their authors tested this application. Private badge
captures used during development are not distributed.
