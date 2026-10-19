// SPDX-License-Identifier: GPL-3.0-only
#include "hitag2_edge_decode.h"

#include <string.h>

#define MAX_POINTS 1024U
#define MAX_PEAKS  128U
#define SOF_EDGES  10U
#define FRAME_BITS 37U

static uint16_t peak_threshold(const uint16_t* values, size_t count) {
    uint16_t top[12] = {0};
    uint16_t baseline[10];
    memcpy(baseline, values, sizeof(baseline));
    for(size_t i = 1U; i < 10U; i++) {
        uint16_t value = baseline[i];
        size_t j = i;
        while(j && baseline[j - 1U] > value) {
            baseline[j] = baseline[j - 1U];
            j--;
        }
        baseline[j] = value;
    }
    for(size_t i = 0; i < count; i++) {
        uint16_t value = values[i];
        for(size_t j = 0; j < 12U; j++) {
            if(value > top[j]) {
                uint16_t previous = top[j];
                top[j] = value;
                value = previous;
            }
        }
    }
    uint32_t rank = (count - 1U) / 100U;
    uint32_t fraction = (count - 1U) % 100U;
    uint32_t p99_x100 = top[rank] * (100U - fraction) + top[rank + 1U] * fraction;
    uint32_t relative = (p99_x100 * 8U + 9999U) / 10000U;
    uint32_t floor = ((uint32_t)baseline[4] + baseline[5] + 1U) / 2U + 8U;
    return (uint16_t)(relative > floor ? relative : floor);
}

bool hitag2_edge_decode(
    const uint16_t* mad,
    size_t count,
    uint16_t step_us,
    uint16_t start_us,
    Hitag2EdgeDecode* result) {
    if(!result) return false;
    memset(result, 0, sizeof(*result));
    result->status = Hitag2EdgeBadInput;
    if(!mad || count < 10U || count > MAX_POINTS || step_us != 16U || start_us > 3000U)
        return false;

    result->threshold = peak_threshold(mad, count);
    uint16_t peaks[MAX_PEAKS];
    size_t n = 0U;
    for(size_t i = 1U; i + 1U < count; i++) {
        if(mad[i] < result->threshold || mad[i] <= mad[i - 1U]) continue;
        size_t end = i;
        while(end + 1U < count && mad[end + 1U] == mad[i])
            end++;
        if(end + 1U < count && mad[end + 1U] < mad[i]) {
            uint16_t peak = (uint16_t)((i + end) / 2U);
            if(n && (uint32_t)peak - peaks[n - 1U] < 4U) {
                if(mad[peak] > mad[peaks[n - 1U]]) peaks[n - 1U] = peak;
            } else {
                if(n == MAX_PEAKS) {
                    result->status = Hitag2EdgeOverflow;
                    return false;
                }
                peaks[n++] = peak;
            }
        }
        i = end;
    }
    result->peak_count = (uint16_t)n;
    size_t first = 0U;
    while(first < n && start_us + 15U + (uint32_t)peaks[first] * step_us < 1100U)
        first++;
    if(first == n || start_us + 15U + (uint32_t)peaks[first] * step_us > 2200U) {
        result->status = Hitag2EdgeNoOnset;
        return false;
    }
    if(n - first < SOF_EDGES) {
        result->status = Hitag2EdgeBadSof;
        return false;
    }

    int32_t sum_t = 0;
    int32_t sum_kt = 0;
    for(size_t k = 0; k < SOF_EDGES; k++) {
        int32_t t = start_us + 15U + (uint32_t)peaks[first + k] * step_us;
        sum_t += t;
        sum_kt += (int32_t)k * t;
    }
    result->half_q8 = ((10 * sum_kt - 45 * sum_t) * 256) / 825;
    result->onset_q8 = (sum_t * 256 - result->half_q8 * 45) / 10;
    uint32_t max_error = 0U;
    for(size_t k = 0; k < SOF_EDGES; k++) {
        int32_t t_q8 = (start_us + 15U + (uint32_t)peaks[first + k] * step_us) * 256;
        int32_t error = t_q8 - result->onset_q8 - (int32_t)k * result->half_q8;
        uint32_t absolute = (uint32_t)(error < 0 ? -error : error);
        if(absolute > max_error) max_error = absolute;
    }
    result->sof_error_q8 = (uint16_t)(max_error > UINT16_MAX ? UINT16_MAX : max_error);
    if(result->half_q8 < 120 * 256 || result->half_q8 > 136 * 256 || max_error > 24U * 256U) {
        result->status = Hitag2EdgeBadSof;
        return false;
    }
    int32_t final_center = result->onset_q8 + result->half_q8 * 147 / 2;
    if(final_center > (int32_t)(start_us + 15U + (count - 1U) * step_us) * 256) {
        result->status = Hitag2EdgeShortWindow;
        return false;
    }

    size_t edge = first;
    bool first_low = false;
    bool sof_ok = true;
    for(size_t half = 0; half < 2U * FRAME_BITS; half++) {
        int32_t center = result->onset_q8 + (int32_t)(2U * half + 1U) * result->half_q8 / 2;
        while(edge < n &&
              (int32_t)(start_us + 15U + (uint32_t)peaks[edge] * step_us) * 256 <= center)
            edge++;
        bool low = ((edge - first) & 1U) != 0U;
        if((half & 1U) == 0U) {
            first_low = low;
        } else {
            if(first_low == low) result->errors++;
            size_t bit = half / 2U;
            if(bit < 5U) {
                if(!first_low || low) sof_ok = false;
            } else {
                result->word = (result->word << 1U) | (first_low ? 1U : 0U);
            }
        }
    }
    if(!sof_ok) {
        result->status = Hitag2EdgeBadSof;
        return false;
    }
    result->status = result->errors ? Hitag2EdgeManchester : Hitag2EdgeOk;
    return result->status == Hitag2EdgeOk;
}
