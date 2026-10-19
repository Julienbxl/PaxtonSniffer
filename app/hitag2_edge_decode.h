// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    Hitag2EdgeOk = 0,
    Hitag2EdgeNoOnset,
    Hitag2EdgeBadSof,
    Hitag2EdgeShortWindow,
    Hitag2EdgeManchester,
    Hitag2EdgeBadInput,
    Hitag2EdgeOverflow,
} Hitag2EdgeStatus;

typedef struct {
    uint32_t word;
    int32_t onset_q8;
    int32_t half_q8;
    uint16_t peak_count;
    uint16_t threshold;
    uint16_t sof_error_q8;
    uint8_t errors;
    uint8_t status;
} Hitag2EdgeDecode;

/* MAD describes transitions here. Recover levels by toggling at each peak,
 * with the clock fitted only to the first ten SOF transitions. */
bool hitag2_edge_decode(
    const uint16_t* mad,
    size_t count,
    uint16_t step_us,
    uint16_t start_us,
    Hitag2EdgeDecode* result);
