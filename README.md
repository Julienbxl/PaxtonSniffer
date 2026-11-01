# PaxtonSniffer V1

Capture Paxton badges with Flipper Zero and export EM4100 files.
Tested with fobs and cards.

## Use

1. Launch **Paxton Sniffer V1**. Hold the Flipper and your fob/card together against the wall reader for a few seconds, adjusting their position slightly if needed.
2. Choose **Save** when prompted. Open the saved file in **125 kHz RFID**.
3. **Emulate**, or **Write** to a compatible **T5577**.

**Avoid readers mounted on metal. Keep the same single badge throughout the capture.**

## Firmware And Installation

The included **custom Unleashed 093** adds ADC/DMA capture from the internal 125 kHz antenna (API 88.11). No hardware modification is needed; stock firmware cannot run this app.

1. Back up your Flipper, then install the [firmware update](firmware/flipper-z-f7-update-paxton-sniffer-v1.tgz) using qFlipper's **Install from file**.
2. Copy [PaxtonSniffer.fap](PaxtonSniffer.fap) to the SD card's `apps/RFID/` folder.

Use only with badges and systems you are authorized to test.
