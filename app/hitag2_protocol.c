// SPDX-License-Identifier: GPL-3.0-only
#include <furi.h>
#include <furi_hal.h>
#include <gui/elements.h>
#include <gui/gui.h>
#include <gui/view_port.h>
#include <input/input.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>

#include "hitag2_hal_ext.h"
#include "hitag2_edge_decode.h"

#define TAG "HT2SNIFF"
#define DIRECT_CONFIRMATIONS 2U
#define RFID_DIR "/ext/lfrfid"

typedef struct {
    uint32_t word;
    uint32_t reader_us;
    uint8_t count;
    char digits[9];
} DirectCandidate;

static DirectCandidate direct_pages[2][4];
static bool capture_ready;
static bool capture_active;
static uint32_t captured_id;
static char captured_digits[9];

static const DirectCandidate* best_direct_candidate(uint32_t page) {
    const DirectCandidate* best = &direct_pages[page][0];
    for(uint32_t i = 1; i < 4U; i++) {
        if(direct_pages[page][i].count > best->count) best = &direct_pages[page][i];
    }
    return best;
}

static bool observe_direct_page(
    const char* label,
    const uint8_t* bits,
    uint32_t bit_count,
    uint32_t errors,
    bool phase_locked,
    uint32_t reader_us,
    bool paxton_ok,
    const char* paxton) {
    if(!phase_locked || errors || bit_count != 32U || !paxton_ok || reader_us == UINT32_MAX)
        return false;
    uint32_t page = strcmp(label, "E0") == 0 ? 0U : strcmp(label, "E8") == 0 ? 1U : 2U;
    if(page > 1U) return false;
    if(page == 0U) {
        if(strlen(paxton) != 6U || strspn(paxton, "0123456789") != 6U) return false;
    } else {
        if(strlen(paxton) != 3U || strspn(paxton, "0123456789") != 2U || paxton[2] != 'F')
            return false;
    }

    uint32_t word = 0U;
    for(uint32_t i = 0; i < 32U; i++) word = (word << 1U) | (bits[i] & 1U);
    DirectCandidate* slots = direct_pages[page];
    DirectCandidate* slot = NULL;
    for(uint32_t i = 0; i < 4U; i++) {
        if(slots[i].count && slots[i].word == word) {
            slot = &slots[i];
            break;
        }
    }
    if(!slot) {
        for(uint32_t i = 0; i < 4U; i++) {
            if(!slots[i].count) {
                slot = &slots[i];
                slot->word = word;
                strncpy(slot->digits, paxton, sizeof(slot->digits) - 1U);
                break;
            }
        }
    }
    if(!slot || (slot->count && reader_us <= slot->reader_us)) return false;
    slot->reader_us = reader_us;
    if(slot->count < UINT8_MAX) slot->count++;

    DirectCandidate* winner[2] = {NULL, NULL};
    for(uint32_t p = 0; p < 2U; p++) {
        bool tied = false;
        for(uint32_t i = 0; i < 4U; i++) {
            DirectCandidate* candidate = &direct_pages[p][i];
            if(candidate->count < DIRECT_CONFIRMATIONS) continue;
            if(!winner[p] || candidate->count > winner[p]->count) {
                winner[p] = candidate;
                tied = false;
            } else if(candidate->count == winner[p]->count) {
                tied = true;
            }
        }
        if(!winner[p] || tied) return false;
    }
    char joined[9];
    memcpy(joined, winner[0]->digits, 6U);
    joined[6] = winner[1]->digits[0];
    joined[7] = winner[1]->digits[1];
    joined[8] = '\0';
    uint32_t id = 0U;
    for(uint32_t i = 0; i < 8U; i++) id = id * 10U + (uint32_t)(joined[i] - '0');
    captured_id = id;
    memcpy(captured_digits, joined, sizeof(joined));
    capture_ready = true;
    return true;
}

/*
 * Passive compact Hitag2 / Paxton sniffer.
 *
 * ADC1_IN14 / RFID_RF_IN is streamed continuously with the LF antenna
 * configured in the V17-compatible receive state. Per-response MAD edge
 * decoding runs alongside the live segment decoder.
 */

#define SAMPLE_RATE_HZ 500000U
#define ADC_SAMPLE_US (1000000U / SAMPLE_RATE_HZ)
#define BLOCK_SAMPLES 8U
#define BLOCK_US (BLOCK_SAMPLES * ADC_SAMPLE_US)

#define STREAM_SAMPLES 8192U
#define STREAM_HALF_SAMPLES (STREAM_SAMPLES / 2U)
#define PROCESS_CHUNK_SAMPLES 2048U

#define RAW_PAGE_COUNT 2U
#define RAW_CAPTURE_START_DT_US 800U
#define RAW_CAPTURE_SAMPLES 6000U
#define RAW_CAPTURE_PACKED_BYTES ((RAW_CAPTURE_SAMPLES * 3U) / 2U)
#define RAW_CAPTURE_DUMP_VALUES 16U
#define RAW_HISTORY_SAMPLES 8192U

#define PAGE_CAPTURE_MAX_REPEATS 65535U
#define PAGE_BASEBAND_WINDOW_SAMPLES 16U
#define PAGE_BASEBAND_STEP_SAMPLES 8U
#define PAGE_BASEBAND_STEP_US (PAGE_BASEBAND_STEP_SAMPLES * ADC_SAMPLE_US)
#define PAGE_BASEBAND_POINTS \
    (((RAW_CAPTURE_SAMPLES - PAGE_BASEBAND_WINDOW_SAMPLES) / PAGE_BASEBAND_STEP_SAMPLES) + 1U)
#define PAGE_BASEBAND_DUMP_VALUES 12U

#define CAPTURE_DIR "/ext/paxton_sniffer"
#define LOG_PATH_FMT "/ext/paxton_sniffer/sniff_%03u.txt"

#define HT2_T0_US 8U
#define HT2_LONG_GAP_US 640U
#define HT2_READER_STOP_MIN_US 272U
#define TAG_AC_DC_SHIFT 6U
#define TAG_AC_ABS_SHIFT 4U
#define TAG_AC_MIN_ABS_Q8 (2U * 256U)  // lowered for small tag load-mod on carrier (real response is small ripple, not deep lows)
#define TAG_AC_HYST_MIN_Q8 64U
#define TAG_RESPONSE_MAX_US 40000U

// Round tag segments to multiples of the measured Manchester half-bit.
#define TAG_NRZ_UNIT_US 127U
#define TAG_NRZ_MAX_UNITS 6U

#define MAX_FRAME_SEGMENTS 160U
#define MAX_FRAME_BITS 96U
#define MAX_LINE 384U
#define TAG_SOF_BITS 5U
#define TAG_UID_BITS 32U
#define TAG_PHASE_MAX_ERRORS 4U
#define TAG_PHASE_MAX_PREFIX_BITS 2U
/*
 * The AC segmenter can enter a weak tag frame a few envelope blocks late or
 * retain a short leading disturbance. Keep timing as a coarse association
 * gate only; the five valid SOF bits still provide the phase lock.
 */
#define TAG_PHASE_DT_MIN_US 800U
#define TAG_PHASE_DT_MAX_US 3000U
#define TAG_DIAG_LIMIT 24U

typedef struct {
    FuriMessageQueue* input_queue;
} Hitag2Ui;

typedef struct {
    bool state_low;
    bool has_state;
    uint32_t start_us;
    uint32_t duration_us;
    uint32_t mean_sum;
    uint32_t blocks;
    uint16_t min_v;
    uint16_t max_v;
} SegmentBuilder;

typedef struct {
    bool low;
    uint32_t start_us;
    uint32_t duration_us;
    uint16_t mean_v;
    uint16_t min_v;
    uint16_t max_v;
} Segment;

typedef struct {
    Segment seg[MAX_FRAME_SEGMENTS];
    uint32_t count;
} FrameBuffer;

typedef struct {
    uint16_t low_level;
    uint16_t high_level;
    uint16_t threshold;
    bool initialized;
} EnvelopeLevels;

typedef struct {
    bool initialized;
    int32_t dc_q8;
    uint32_t abs_q8;
    uint16_t envelope_history[3];
    uint32_t envelope_sum;
    uint8_t envelope_pos;
    uint8_t envelope_count;
} TagAcState;

typedef enum {
    TagDropNone = 0,
    TagDropNoNrz,
    TagDropNoManchester,
    TagDropNoHeader,
    TagDropPayloadShort,
    TagDropAllSame,
} TagDropReason;

typedef struct {
    uint32_t reader_invalid;
    uint32_t reader_drop_bad_order;
    uint32_t reader_drop_low_range;
    uint32_t reader_drop_total_range;
    uint32_t reader_drop_too_short;
    uint32_t reader_pair_low_min;
    uint32_t reader_pair_low_max;
    uint32_t reader_pair_total_min;
    uint32_t reader_pair_total_max;
    uint32_t reader_adaptive_frames;
    uint32_t reader_adaptive_attempts;
    uint32_t reader_unrecognized;
    uint32_t reader_password_fuzzy_accepts;
    uint32_t tag_invalid;
    uint32_t tag_drop_no_nrz;
    uint32_t tag_drop_no_manchester;
    uint32_t tag_drop_no_header;
    uint32_t tag_drop_payload_short;
    uint32_t tag_drop_all_same;
    uint32_t tag_carrier_cuts;
    uint32_t tag_reader_low_skips;
    uint32_t tag_wait_reader_skips;
    uint32_t tag_adaptive_frames;
    uint32_t tag_adaptive_attempts;
    uint32_t tag_seg_1t;
    uint32_t tag_seg_2t;
    uint32_t tag_seg_3t;
    uint32_t tag_seg_long;
    uint32_t tag_window_timeouts;
    uint32_t reader_gate_resets;
    uint32_t tag_strong;
    uint32_t tag_weak;
    uint32_t tag_header_run_promotions;
    uint32_t tag_phase_locked;
    uint32_t tag_phase_prefix_restores;
    uint32_t tag_phase_rejects;
    uint32_t tag_diag_lines;
} DecodeStats;

typedef struct {
    uint16_t seen;
    uint16_t captures;
    uint16_t busy_drops;
    uint16_t history_losses;
} PageAccumulator;

typedef struct {
    bool armed;
    uint8_t page_index;
    const char* command;
    uint32_t command_end_us;
    uint64_t start_sample;
    uint32_t copied_points;
} PageCapture;

typedef struct {
    bool armed;
    bool complete;
    uint8_t page;
    const char* command;
    uint32_t command_end_us;
    uint64_t start_sample;
    uint32_t copied;
} RawDiagnosticCapture;

static uint16_t stream_buf[STREAM_SAMPLES];
static uint16_t processing_half[STREAM_HALF_SAMPLES];
static uint16_t block_means[PROCESS_CHUNK_SAMPLES / BLOCK_SAMPLES];
static volatile uint32_t stream_completed_halves;
static volatile uint32_t stream_dropped_halves;
static uint32_t stream_gap_events;
static uint32_t stream_pending_peak;
static volatile uint32_t ui_reader_frames;
static char log_buffer[4096];
static size_t log_buffer_used;
static uint8_t raw_diagnostic_samples[RAW_CAPTURE_PACKED_BYTES];
static RawDiagnosticCapture raw_diagnostic_capture;
static uint16_t page_mad[PAGE_BASEBAND_POINTS];
static PageAccumulator page_accumulators[RAW_PAGE_COUNT];
static PageCapture page_capture_state;
static uint16_t raw_history[RAW_HISTORY_SAMPLES];
static uint64_t raw_history_start;
static uint64_t raw_history_end;
static const char* const page_commands[RAW_PAGE_COUNT] = {"E0", "E8"};
static uint16_t edge_valid_frames[RAW_PAGE_COUNT];

#define EDGE_EVENT_COUNT 64U
typedef struct {
    uint32_t reader_us;
    Hitag2EdgeDecode decoded;
    uint8_t page;
    bool paxton_ok;
} EdgeEvent;

static EdgeEvent edge_events[EDGE_EVENT_COUNT];
static uint32_t edge_event_total;

static EnvelopeLevels reader_levels_state;
static TagAcState tag_ac_state;
static SegmentBuilder reader_builder_state;
static FrameBuffer reader_frame_state;
static SegmentBuilder tag_builder_state;
static FrameBuffer tag_frame_state;
static DecodeStats decode_stats_state;
/* V12: label of the most recently recognized reader command, updated
 * alongside last_reader_us in log_reader_frame(). Points at a string
 * literal (static storage duration), so it is always safe to hold onto
 * regardless of how long it takes a caller to print it. */
static const char* g_last_reader_label = "NONE";
static void write_line(File* file, const char* line);
static bool paxton_digits_from_bits(
    const uint8_t* bits,
    uint32_t bit_count,
    char* out,
    size_t out_size,
    uint32_t* digit_count_out);

static int32_t page_index_from_label(const char* label) {
    if(strcmp(label, "E0") == 0) return 0;
    if(strcmp(label, "E8") == 0) return 1;
    return -1;
}

static void arm_page_capture(const char* label, uint32_t command_end_us) {
    int32_t index = page_index_from_label(label);
    if(index < 0) return;

    PageAccumulator* accumulator = &page_accumulators[index];
    if(accumulator->seen < UINT16_MAX) accumulator->seen++;
    if(page_capture_state.armed) {
        if(accumulator->busy_drops < UINT16_MAX) accumulator->busy_drops++;
        return;
    }

    page_capture_state.armed = true;
    page_capture_state.page_index = (uint8_t)index;
    page_capture_state.command = label;
    page_capture_state.command_end_us = command_end_us;
    page_capture_state.start_sample =
        ((uint64_t)command_end_us + RAW_CAPTURE_START_DT_US) * SAMPLE_RATE_HZ / 1000000U;
    page_capture_state.copied_points = 0U;

    if(!raw_diagnostic_capture.armed && !raw_diagnostic_capture.complete) {
        memset(raw_diagnostic_samples, 0, sizeof(raw_diagnostic_samples));
        raw_diagnostic_capture.armed = true;
        raw_diagnostic_capture.page = (uint8_t)(index + 4);
        raw_diagnostic_capture.command = label;
        raw_diagnostic_capture.command_end_us = command_end_us;
        raw_diagnostic_capture.start_sample = page_capture_state.start_sample;
        raw_diagnostic_capture.copied = 0U;
    }
}

static void raw_capture_set(uint32_t sample_index, uint16_t value) {
    uint32_t pair = sample_index / 2U;
    uint32_t offset = pair * 3U;
    value &= 0x0FFFU;
    if((sample_index & 1U) == 0U) {
        raw_diagnostic_samples[offset] = (uint8_t)value;
        raw_diagnostic_samples[offset + 1U] = (uint8_t)(value >> 8);
    } else {
        raw_diagnostic_samples[offset + 1U] |= (uint8_t)((value & 0x0FU) << 4);
        raw_diagnostic_samples[offset + 2U] = (uint8_t)(value >> 4);
    }
}

static uint16_t raw_capture_get(uint32_t sample_index) {
    uint32_t pair = sample_index / 2U;
    uint32_t offset = pair * 3U;
    if((sample_index & 1U) == 0U) {
        return (uint16_t)(raw_diagnostic_samples[offset] |
                          ((uint16_t)(raw_diagnostic_samples[offset + 1U] & 0x0FU) << 8));
    }
    return (uint16_t)((raw_diagnostic_samples[offset + 1U] >> 4) |
                      ((uint16_t)raw_diagnostic_samples[offset + 2U] << 4));
}

static void append_raw_history(
    const uint16_t* samples,
    uint64_t sample_abs_start,
    uint32_t sample_count) {
    if(sample_abs_start != raw_history_end) raw_history_start = sample_abs_start;
    for(uint32_t sample = 0; sample < sample_count; sample++) {
        raw_history[(sample_abs_start + sample) % RAW_HISTORY_SAMPLES] = samples[sample];
    }
    raw_history_end = sample_abs_start + sample_count;
    if(raw_history_end - raw_history_start > RAW_HISTORY_SAMPLES) {
        raw_history_start = raw_history_end - RAW_HISTORY_SAMPLES;
    }
}

static uint16_t history_sample(uint64_t sample) {
    return raw_history[sample % RAW_HISTORY_SAMPLES];
}

static void collect_raw_diagnostic_samples(void) {
    RawDiagnosticCapture* capture = &raw_diagnostic_capture;
    if(!capture->armed || capture->complete || raw_history_end <= capture->start_sample) return;

    uint64_t wanted = capture->start_sample + capture->copied;
    if(wanted < raw_history_start) {
        capture->armed = false;
        capture->copied = 0U;
        return;
    }
    if(wanted >= raw_history_end) return;

    uint32_t available = (uint32_t)(raw_history_end - wanted);
    uint32_t remaining = RAW_CAPTURE_SAMPLES - capture->copied;
    uint32_t count = available < remaining ? available : remaining;
    for(uint32_t sample = 0; sample < count; sample++) {
        raw_capture_set(capture->copied + sample, history_sample(wanted + sample));
    }
    capture->copied += count;
    if(capture->copied == RAW_CAPTURE_SAMPLES) {
        capture->complete = true;
        capture->armed = false;
    }
}

static uint32_t abs_i32(int32_t value) {
    return (uint32_t)(value < 0 ? -value : value);
}

static uint16_t compute_page_mad_window(uint64_t window_start) {
    uint32_t sum = 0U;
    for(uint32_t sample = 0; sample < PAGE_BASEBAND_WINDOW_SAMPLES; sample++) {
        sum += history_sample(window_start + sample);
    }
    uint16_t mean = (uint16_t)(sum / PAGE_BASEBAND_WINDOW_SAMPLES);

    uint32_t deviation_sum = 0U;
    for(uint32_t sample = 0; sample < PAGE_BASEBAND_WINDOW_SAMPLES; sample++) {
        int32_t centered = (int32_t)history_sample(window_start + sample) - mean;
        deviation_sum += abs_i32(centered);
    }

    return (uint16_t)(deviation_sum / PAGE_BASEBAND_WINDOW_SAMPLES);
}

static void abort_page_capture_for_history_loss(void) {
    PageAccumulator* accumulator = &page_accumulators[page_capture_state.page_index];
    if(accumulator->history_losses < UINT16_MAX) accumulator->history_losses++;
    page_capture_state.armed = false;
    page_capture_state.copied_points = 0U;
}

static void collect_page_baseband(void) {
    if(!page_capture_state.armed) return;

    while(page_capture_state.copied_points < PAGE_BASEBAND_POINTS) {
        uint64_t wanted = page_capture_state.start_sample +
                          (uint64_t)page_capture_state.copied_points * PAGE_BASEBAND_STEP_SAMPLES;
        if(wanted < raw_history_start) {
            abort_page_capture_for_history_loss();
            return;
        }
        if(wanted + PAGE_BASEBAND_WINDOW_SAMPLES > raw_history_end) return;

        uint32_t point = page_capture_state.copied_points;
        page_mad[point] = compute_page_mad_window(wanted);
        page_capture_state.copied_points++;
    }

    uint32_t page_index = page_capture_state.page_index;
    EdgeEvent* event = &edge_events[edge_event_total++ % EDGE_EVENT_COUNT];
    event->reader_us = page_capture_state.command_end_us;
    event->page = (uint8_t)page_index;
    event->paxton_ok = false;
    if(hitag2_edge_decode(
           page_mad,
           PAGE_BASEBAND_POINTS,
           PAGE_BASEBAND_STEP_US,
           RAW_CAPTURE_START_DT_US,
           &event->decoded)) {
        uint8_t bits[TAG_UID_BITS];
        for(uint32_t bit = 0; bit < TAG_UID_BITS; bit++)
            bits[bit] = (uint8_t)((event->decoded.word >> (31U - bit)) & 1U);
        char paxton[32];
        uint32_t digits = 0U;
        bool parity = paxton_digits_from_bits(bits, TAG_UID_BITS, paxton, sizeof(paxton), &digits);
        event->paxton_ok = parity &&
                           ((page_index == 0U && digits == 6U && strspn(paxton, "0123456789") == 6U) ||
                            (page_index == 1U && digits == 3U && strspn(paxton, "0123456789") == 2U && paxton[2] == 'F'));
        if(event->paxton_ok) {
            if(edge_valid_frames[page_index] < UINT16_MAX) edge_valid_frames[page_index]++;
            observe_direct_page(
                page_capture_state.command, bits, TAG_UID_BITS, 0U, true,
                page_capture_state.command_end_us, parity, paxton);
        }
    }
    if(page_accumulators[page_index].captures < UINT16_MAX) {
        page_accumulators[page_index].captures++;
    }
    page_capture_state.armed = false;
}

static void collect_page_captures(void) {
    collect_raw_diagnostic_samples();
    collect_page_baseband();
}

static void dump_raw_diagnostic_capture(File* file) {
    const RawDiagnosticCapture* capture = &raw_diagnostic_capture;
    char line[MAX_LINE];
    snprintf(
        line,
        sizeof(line),
        "RAW_PAGE page=%u cmd=%s complete=%u cmd_end_us=%lu start_dt_us=%u rate=%u n=%lu policy=first_page_only\n",
        capture->page,
        capture->command ? capture->command : "NONE",
        capture->complete ? 1U : 0U,
        (unsigned long)capture->command_end_us,
        (unsigned int)RAW_CAPTURE_START_DT_US,
        (unsigned int)SAMPLE_RATE_HZ,
        (unsigned long)capture->copied);
    write_line(file, line);

    if(!capture->complete) return;
    for(uint32_t offset = 0; offset < RAW_CAPTURE_SAMPLES; offset += RAW_CAPTURE_DUMP_VALUES) {
        size_t position = (size_t)snprintf(
            line,
            sizeof(line),
            "RAW_PAGE_DATA page=%u offset=%lu:",
            capture->page,
            (unsigned long)offset);
        uint32_t end = offset + RAW_CAPTURE_DUMP_VALUES;
        if(end > RAW_CAPTURE_SAMPLES) end = RAW_CAPTURE_SAMPLES;
        for(uint32_t sample = offset; sample < end && position < sizeof(line); sample++) {
            position += (size_t)snprintf(
                line + position,
                sizeof(line) - position,
                " %u",
                raw_capture_get(sample));
        }
        if(position + 1U < sizeof(line)) {
            line[position++] = '\n';
            line[position] = '\0';
        }
        write_line(file, line);
    }
}

static void draw_callback(Canvas* canvas, void* context) {
    UNUSED(context);

    char text[128];
    snprintf(
        text,
        sizeof(text),
        "\e#Paxton Sniffer V1\e#\n"
        "E0 %u  E8 %u\n"
        "2 reads per page\n"
        "R %lu  Drop %lu\n"
        "Back: stop",
        best_direct_candidate(0)->count,
        best_direct_candidate(1)->count,
        (unsigned long)ui_reader_frames,
        (unsigned long)stream_dropped_halves);

    canvas_clear(canvas);
    elements_text_box(
        canvas,
        0,
        0,
        canvas_width(canvas),
        canvas_height(canvas),
        AlignCenter,
        AlignCenter,
        text,
        false);
}

static void input_callback(InputEvent* input_event, void* context) {
    Hitag2Ui* ui = context;
    furi_message_queue_put(ui->input_queue, input_event, 0);
}

static bool should_abort_from_input(FuriMessageQueue* input_queue) {
    InputEvent event;
    while(furi_message_queue_get(input_queue, &event, 0) == FuriStatusOk) {
        if((event.key == InputKeyBack) &&
           ((event.type == InputTypeShort) || (event.type == InputTypeLong))) {
            return true;
        }
    }

    return false;
}

static bool file_exists(Storage* storage, const char* path) {
    FileInfo info;
    return storage_common_stat(storage, path, &info) == FSE_OK;
}

static bool find_free_log_path(Storage* storage, char* path, size_t path_size, uint32_t* index_out) {
    for(uint32_t i = 0; i < 1000U; i++) {
        snprintf(path, path_size, LOG_PATH_FMT, (unsigned int)i);
        if(!file_exists(storage, path)) {
            if(index_out) *index_out = i;
            return true;
        }
    }
    return false;
}

static bool offer_save_credential(Storage* storage) {
    char path[96];
    char preview[96];
    snprintf(
        preview,
        sizeof(preview),
        "Paxton %s\nEM 00%08lX\nE0/E8 confirmed x2",
        captured_digits,
        (unsigned long)captured_id);
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogMessage* message = dialog_message_alloc();
    dialog_message_set_header(message, "Save EM4100?", 64, 0, AlignCenter, AlignTop);
    dialog_message_set_text(message, preview, 64, 32, AlignCenter, AlignCenter);
    dialog_message_set_buttons(message, "Cancel", NULL, "Save");
    bool confirmed = dialog_message_show(dialogs, message) == DialogMessageButtonRight;
    bool saved = false;
    if(confirmed) {
        storage_common_mkdir(storage, RFID_DIR);
        for(uint32_t suffix = 0; suffix < 100U; suffix++) {
            if(suffix == 0U) {
                snprintf(path, sizeof(path), RFID_DIR "/Paxton_%s.rfid", captured_digits);
            } else {
                snprintf(path, sizeof(path), RFID_DIR "/Paxton_%s_%lu.rfid", captured_digits, (unsigned long)suffix);
            }
            if(!file_exists(storage, path)) break;
            path[0] = '\0';
        }
        if(path[0]) {
            char content[128];
            int length = snprintf(
                content,
                sizeof(content),
                "Filetype: Flipper RFID key\nVersion: 1\nKey type: EM4100\nData: 00 %02lX %02lX %02lX %02lX\n",
                (unsigned long)((captured_id >> 24U) & 0xFFU),
                (unsigned long)((captured_id >> 16U) & 0xFFU),
                (unsigned long)((captured_id >> 8U) & 0xFFU),
                (unsigned long)(captured_id & 0xFFU));
            File* file = storage_file_alloc(storage);
            if(length > 0 && (size_t)length < sizeof(content) &&
               storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_NEW)) {
                saved = storage_file_write(file, content, (size_t)length) == (size_t)length;
                storage_file_close(file);
                if(!saved) storage_common_remove(storage, path);
            }
            storage_file_free(file);
        }
        if(!saved) {
            dialog_message_set_header(message, "Save failed", 64, 0, AlignCenter, AlignTop);
            dialog_message_set_text(message, "Check SD card", 64, 30, AlignCenter, AlignCenter);
            dialog_message_set_buttons(message, NULL, "OK", NULL);
            dialog_message_show(dialogs, message);
        }
    }
    dialog_message_free(message);
    furi_record_close(RECORD_DIALOGS);
    return saved;
}

static void stream_callback(bool first_half, void* context) {
    UNUSED(context);
    UNUSED(first_half);
    stream_completed_halves++;
}

static bool copy_latest_stream_half(uint32_t last_sequence, uint32_t* sequence) {
    for(uint32_t attempt = 0; attempt < 3U; attempt++) {
        uint32_t current = stream_completed_halves;
        if(current == 0U || current == last_sequence) return false;
        uint32_t half_index = (current - 1U) & 1U;
        memcpy(
            processing_half,
            stream_buf + half_index * STREAM_HALF_SAMPLES,
            sizeof(processing_half));
        if(stream_completed_halves == current) {
            *sequence = current;
            return true;
        }
    }
    return false;
}

static void flush_log(File* file) {
    if(log_buffer_used == 0U) return;
    storage_file_write(file, log_buffer, log_buffer_used);
    log_buffer_used = 0U;
}

static void write_line(File* file, const char* line) {
    if(capture_active) return;
    size_t length = strlen(line);
    if(length > sizeof(log_buffer) - log_buffer_used) flush_log(file);
    if(length > sizeof(log_buffer)) {
        storage_file_write(file, line, length);
        return;
    }
    memcpy(log_buffer + log_buffer_used, line, length);
    log_buffer_used += length;
}

static void bits_to_hex(const uint8_t* bits, uint32_t bit_count, char* out, size_t out_size) {
    size_t pos = 0;
    uint32_t whole = bit_count / 8U;
    for(uint32_t i = 0; i < whole && pos + 2U < out_size; i++) {
        uint8_t v = 0;
        for(uint32_t b = 0; b < 8U; b++) {
            v = (uint8_t)((v << 1) | (bits[i * 8U + b] & 1U));
        }
        pos += snprintf(out + pos, out_size - pos, "%02X", (unsigned int)v);
    }
    if(pos < out_size) {
        out[pos] = '\0';
    }
}

static void bits_to_string(const uint8_t* bits, uint32_t bit_count, char* out, size_t out_size) {
    uint32_t n = bit_count;
    if(n + 1U > out_size) n = out_size - 1U;
    for(uint32_t i = 0; i < n; i++) {
        out[i] = bits[i] ? '1' : '0';
    }
    out[n] = '\0';
}

static void dump_edge_captures(File* file) {
    char line[MAX_LINE];
    for(uint32_t page = 0; page < RAW_PAGE_COUNT; page++) {
        const PageAccumulator* capture = &page_accumulators[page];
        snprintf(
            line, sizeof(line),
            "EDGE_CAPTURE cmd=%s seen=%u complete=%u valid=%u busy=%u history_loss=%u\n",
            page_commands[page], capture->seen, capture->captures, edge_valid_frames[page],
            capture->busy_drops, capture->history_losses);
        write_line(file, line);
    }
    uint32_t first = edge_event_total > EDGE_EVENT_COUNT ? edge_event_total - EDGE_EVENT_COUNT : 0U;
    for(uint32_t i = first; i < edge_event_total; i++) {
        const EdgeEvent* event = &edge_events[i % EDGE_EVENT_COUNT];
        snprintf(
            line, sizeof(line),
            "EDGE_WORD cmd=%s cmd_end_us=%lu status=%u parity=%u peaks=%u onset_q8=%ld half_q8=%ld err=%u word=%08lX\n",
            page_commands[event->page], (unsigned long)event->reader_us,
            event->decoded.status, event->paxton_ok ? 1U : 0U,
            event->decoded.peak_count, (long)event->decoded.onset_q8,
            (long)event->decoded.half_q8, event->decoded.errors,
            (unsigned long)event->decoded.word);
        write_line(file, line);
    }
}

static bool paxton_digits_from_bits(
    const uint8_t* bits,
    uint32_t bit_count,
    char* out,
    size_t out_size,
    uint32_t* digit_count_out) {
    size_t pos = 0;
    uint32_t digits = 0;
    bool all_parity_ok = true;

    for(uint32_t i = 0; i + 5U <= bit_count; i += 5U) {
        uint8_t ones = 0;
        for(uint32_t b = 0; b < 5U; b++) {
            if(bits[i + b]) ones++;
        }
        if((ones & 1U) == 0U) {
            all_parity_ok = false;
        }

        uint8_t nibble = 0;
        for(uint32_t b = 1; b < 5U; b++) {
            nibble = (uint8_t)((nibble << 1) | bits[i + b]);
        }

        char ch = '?';
        if(nibble < 10U) {
            ch = (char)('0' + nibble);
        } else if(nibble == 0x0FU) {
            ch = 'F';
        }

        if(pos + 1U < out_size) {
            out[pos++] = ch;
        }
        digits++;
        if(ch == 'F') break;
    }

    if(pos < out_size) out[pos] = '\0';
    if(digit_count_out) *digit_count_out = digits;

    return all_parity_ok && digits > 0U;
}

static bool classify_reader_pair(uint32_t low_us, uint32_t high_us, uint8_t* bit_out) {
    if(low_us < 16U || low_us > 88U) {
        return false;
    }

    uint32_t total = low_us + high_us;
    if(total >= 136U && total <= 184U) {
        *bit_out = 0;
        return true;
    }
    if(total >= 216U && total <= 280U) {
        *bit_out = 1;
        return true;
    }

    return false;
}

static bool try_decode_reader(const FrameBuffer* frame, uint8_t* bits, uint32_t* bit_count_out) {
    uint32_t bit_count = 0;
    uint32_t i = 0;

    while(i + 1U < frame->count && bit_count < MAX_FRAME_BITS) {
        const Segment* low = &frame->seg[i];
        const Segment* high = &frame->seg[i + 1U];

        if(!low->low || high->low) {
            return false;
        }

        uint8_t bit = 0;
        if(!classify_reader_pair(low->duration_us, high->duration_us, &bit)) {
            return false;
        }

        bits[bit_count++] = bit;
        i += 2U;
    }

    if(bit_count < 5U) {
        return false;
    }

    *bit_count_out = bit_count;
    return true;
}

static bool reader_length_plausible(uint32_t bit_count) {
    return bit_count == 5U || bit_count == 10U || bit_count == 32U;
}

static uint32_t abs_diff_u32(uint32_t a, uint32_t b) {
    return (a > b) ? (a - b) : (b - a);
}

static bool classify_reader_pair_adaptive(
    uint32_t low_us,
    uint32_t high_us,
    uint8_t* bit_out,
    uint32_t* score_out) {
    if(low_us < 8U || low_us > 120U) {
        return false;
    }

    uint32_t total = low_us + high_us;
    if(total < 104U || total > 336U) {
        return false;
    }

    uint32_t score0 = abs_diff_u32(total, 160U) + abs_diff_u32(low_us, 40U);
    uint32_t score1 = abs_diff_u32(total, 248U) + abs_diff_u32(low_us, 40U);
    if(score0 <= score1) {
        *bit_out = 0;
        if(score_out) *score_out = score0;
    } else {
        *bit_out = 1;
        if(score_out) *score_out = score1;
    }

    return true;
}

static bool try_decode_reader_adaptive(
    const FrameBuffer* frame,
    uint8_t* bits,
    uint32_t* bit_count_out,
    uint32_t* score_out,
    DecodeStats* stats) {
    if(stats) stats->reader_adaptive_attempts++;

    uint32_t best_bits = 0;
    uint32_t best_score = UINT32_MAX;
    uint8_t best[MAX_FRAME_BITS];

    for(uint32_t offset = 0; offset < 4U && offset + 1U < frame->count; offset++) {
        uint32_t bit_count = 0;
        uint32_t score = 0;
        uint8_t candidate[MAX_FRAME_BITS];
        uint32_t i = offset;

        while(i + 1U < frame->count && bit_count < MAX_FRAME_BITS) {
            const Segment* low = &frame->seg[i];
            const Segment* high = &frame->seg[i + 1U];

            if(!low->low || high->low) {
                break;
            }

            uint8_t bit = 0;
            uint32_t pair_score = 0;
            if(!classify_reader_pair_adaptive(
                   low->duration_us, high->duration_us, &bit, &pair_score)) {
                break;
            }

            candidate[bit_count++] = bit;
            score += pair_score;
            i += 2U;

            if(reader_length_plausible(bit_count)) {
                if(bit_count > best_bits || (bit_count == best_bits && score < best_score)) {
                    best_bits = bit_count;
                    best_score = score;
                    memcpy(best, candidate, bit_count);
                }
            }
        }
    }

    if(best_bits == 0U) {
        return false;
    }

    memcpy(bits, best, best_bits);
    *bit_count_out = best_bits;
    if(score_out) *score_out = best_score;
    return true;
}

static bool classify_reader_pair_diag(
    uint32_t low_us,
    uint32_t high_us,
    uint8_t* bit_out,
    DecodeStats* stats) {
    uint32_t total = low_us + high_us;
    if(stats) {
        if(stats->reader_pair_low_min == 0U || low_us < stats->reader_pair_low_min) {
            stats->reader_pair_low_min = low_us;
        }
        if(low_us > stats->reader_pair_low_max) {
            stats->reader_pair_low_max = low_us;
        }
        if(stats->reader_pair_total_min == 0U || total < stats->reader_pair_total_min) {
            stats->reader_pair_total_min = total;
        }
        if(total > stats->reader_pair_total_max) {
            stats->reader_pair_total_max = total;
        }
    }

    if(low_us < 16U || low_us > 88U) {
        if(stats) stats->reader_drop_low_range++;
        return false;
    }

    if(total >= 136U && total <= 184U) {
        *bit_out = 0;
        return true;
    }
    if(total >= 216U && total <= 280U) {
        *bit_out = 1;
        return true;
    }

    if(stats) stats->reader_drop_total_range++;
    return false;
}

static bool try_decode_reader_diag(
    const FrameBuffer* frame,
    uint8_t* bits,
    uint32_t* bit_count_out,
    DecodeStats* stats) {
    uint32_t bit_count = 0;
    uint32_t i = 0;

    while(i + 1U < frame->count && bit_count < MAX_FRAME_BITS) {
        const Segment* low = &frame->seg[i];
        const Segment* high = &frame->seg[i + 1U];

        if(!low->low || high->low) {
            if(stats) stats->reader_drop_bad_order++;
            return false;
        }

        uint8_t bit = 0;
        if(!classify_reader_pair_diag(low->duration_us, high->duration_us, &bit, stats)) {
            return false;
        }

        bits[bit_count++] = bit;
        i += 2U;
    }

    if(bit_count < 5U) {
        if(stats) stats->reader_drop_too_short++;
        return false;
    }

    *bit_count_out = bit_count;
    return true;
}

static bool frame_decodes_as_reader(const FrameBuffer* frame) {
    uint8_t bits[MAX_FRAME_BITS];
    uint32_t bit_count = 0;
    return try_decode_reader(frame, bits, &bit_count);
}

static uint32_t segment_to_nrz_count(const Segment* segment) {
    /*
     * V11.9b: round to the nearest multiple of the measured tag symbol unit
     * instead of the three wide, never-re-derived buckets (192/512/768 us).
     * Doubling/tripling the empirical ~127 us short segment puts the 1/2/3
     * boundaries at roughly 190/317/444 us -- close to the original lower
     * bound (192) but noticeably tighter above it. Anything beyond
     * TAG_NRZ_MAX_UNITS is still treated as garbage/out of range.
     */
    uint32_t count = (segment->duration_us + (TAG_NRZ_UNIT_US / 2U)) / TAG_NRZ_UNIT_US;
    if(count == 0U) count = 1U;
    if(count > TAG_NRZ_MAX_UNITS) return 0U;
    return count;
}

static void update_tag_segment_stats(const FrameBuffer* frame, DecodeStats* stats) {
    if(!stats) return;

    for(uint32_t i = 0; i < frame->count; i++) {
        /* V11.9b: classify with the same rounding rule as segment_to_nrz_count()
         * so the diagnostic line stays consistent with what decoding actually
         * sees. Counts above 2 (i.e. 3..TAG_NRZ_MAX_UNITS) collapse into
         * tag_seg_3t so the log line keeps its existing sym1/sym2/sym3/long
         * shape and stays comparable to V11.7/V11.8 logs. */
        uint32_t count = segment_to_nrz_count(&frame->seg[i]);
        if(count == 0U) {
            stats->tag_seg_long++;
        } else if(count == 1U) {
            stats->tag_seg_1t++;
        } else if(count == 2U) {
            stats->tag_seg_2t++;
        } else {
            stats->tag_seg_3t++;
        }
    }
}

static uint32_t build_nrz(
    const FrameBuffer* frame,
    uint8_t low_bit,
    uint8_t* nrz,
    uint32_t nrz_size) {
    uint32_t out = 0;

    for(uint32_t i = 0; i < frame->count && out < nrz_size; i++) {
        uint32_t count = segment_to_nrz_count(&frame->seg[i]);
        if(count == 0U) break;
        uint8_t state = frame->seg[i].low ? low_bit : (low_bit ^ 1U);
        for(uint32_t j = 0; j < count && out < nrz_size; j++) {
            nrz[out++] = state;
        }
    }

    return out;
}

static uint32_t manchester_decode(
    const uint8_t* nrz,
    uint32_t nrz_count,
    uint8_t invert,
    uint8_t align,
    uint8_t* decoded,
    uint32_t decoded_size,
    uint32_t* errors_out) {
    uint32_t out = 0;
    uint32_t errors = 0;

    for(uint32_t i = align; i + 1U < nrz_count && out < decoded_size; i += 2U) {
        uint8_t a = nrz[i];
        uint8_t b = nrz[i + 1U];
        if(a == 1U && b == 0U) {
            decoded[out++] = invert;
        } else if(a == 0U && b == 1U) {
            decoded[out++] = invert ^ 1U;
        } else {
            errors++;
        }
    }

    if(errors_out) *errors_out = errors;
    return out;
}

typedef struct {
    uint8_t payload[MAX_FRAME_BITS];
    uint32_t payload_bits;
    uint32_t errors;
    uint32_t leading_run;
    uint8_t low_bit;
    uint8_t invert;
    uint8_t align;
    uint8_t prefix_bits;
    uint32_t score;
} TagPhaseCandidate;

/*
 * V14 keeps one output position for every Manchester pair. Older decoders
 * dropped 00/11 pairs completely, shortening the frame and shifting every
 * later bit. Invalid pairs remain errors here, but never alter bit cadence.
 */
static uint32_t manchester_decode_fixed(
    const uint8_t* nrz,
    uint32_t nrz_count,
    uint8_t invert,
    uint8_t align,
    uint8_t* decoded,
    uint8_t* valid,
    uint32_t decoded_size,
    uint32_t* errors_out) {
    uint32_t out = 0;
    uint32_t errors = 0;

    for(uint32_t i = align; i + 1U < nrz_count && out < decoded_size; i += 2U) {
        uint8_t a = nrz[i];
        uint8_t b = nrz[i + 1U];
        if(a == 1U && b == 0U) {
            decoded[out] = invert;
            valid[out] = 1U;
        } else if(a == 0U && b == 1U) {
            decoded[out] = invert ^ 1U;
            valid[out] = 1U;
        } else {
            /* Preserve cadence. The guessed value is explicitly covered by
             * the error count and can never validate a SOF bit. */
            decoded[out] = invert ^ (a == 0U ? 1U : 0U);
            valid[out] = 0U;
            errors++;
        }
        out++;
    }

    if(errors_out) *errors_out = errors;
    return out;
}

static bool try_decode_tag_phase_locked(
    const FrameBuffer* frame,
    uint8_t* payload,
    uint32_t* payload_bits_out,
    uint32_t* errors_out,
    uint32_t* leading_run_out,
    uint8_t* low_bit_out,
    uint8_t* invert_out,
    uint8_t* align_out,
    uint8_t* prefix_bits_out,
    DecodeStats* stats) {
    uint8_t nrz[MAX_FRAME_BITS * 2U];
    uint8_t decoded[MAX_FRAME_BITS];
    uint8_t valid[MAX_FRAME_BITS];
    TagPhaseCandidate best = {.score = UINT32_MAX};

    for(uint8_t low_bit = 0; low_bit < 2U; low_bit++) {
        uint32_t nrz_count = build_nrz(frame, low_bit, nrz, COUNT_OF(nrz));
        if(nrz_count < 16U) continue;

        for(uint8_t invert = 0; invert < 2U; invert++) {
            for(uint8_t align = 0; align < 2U; align++) {
                uint32_t errors = 0;
                uint32_t decoded_count = manchester_decode_fixed(
                    nrz,
                    nrz_count,
                    invert,
                    align,
                    decoded,
                    valid,
                    COUNT_OF(decoded),
                    &errors);
                if(errors > TAG_PHASE_MAX_ERRORS) continue;

                for(uint8_t prefix = 0; prefix <= TAG_PHASE_MAX_PREFIX_BITS; prefix++) {
                    uint32_t total_bits = decoded_count + prefix;
                    if(total_bits < TAG_SOF_BITS + 16U) continue;

                    bool sof_ok = true;
                    for(uint32_t bit = 0; bit < TAG_SOF_BITS; bit++) {
                        if(bit < prefix) continue; // Restored bit is known SOF=1.
                        uint32_t source = bit - prefix;
                        if(source >= decoded_count || !valid[source] || decoded[source] != 1U) {
                            sof_ok = false;
                            break;
                        }
                    }
                    if(!sof_ok) continue;

                    uint32_t payload_bits = total_bits - TAG_SOF_BITS;
                    uint32_t usable_payload = payload_bits;
                    if(usable_payload > TAG_UID_BITS) usable_payload = TAG_UID_BITS;

                    /* Exact SOF+UID length wins. Prefix restoration is allowed
                     * only at the known SOF, never inside the unknown UID. */
                    uint32_t length_error = abs_diff_u32(payload_bits, TAG_UID_BITS);
                    uint32_t score = errors * 128U + length_error * 16U + prefix * 4U + align;
                    if(score >= best.score) continue;

                    uint32_t leading_run = prefix;
                    while(leading_run - prefix < decoded_count &&
                          decoded[leading_run - prefix] == 1U) {
                        leading_run++;
                    }

                    best.payload_bits = usable_payload;
                    best.errors = errors;
                    best.leading_run = leading_run;
                    best.low_bit = low_bit;
                    best.invert = invert;
                    best.align = align;
                    best.prefix_bits = prefix;
                    best.score = score;
                    for(uint32_t bit = 0; bit < usable_payload; bit++) {
                        uint32_t logical = TAG_SOF_BITS + bit;
                        uint32_t source = logical - prefix;
                        best.payload[bit] = decoded[source];
                    }
                }
            }
        }
    }

    if(best.score == UINT32_MAX || best.payload_bits < 16U) {
        if(stats) stats->tag_phase_rejects++;
        return false;
    }

    memcpy(payload, best.payload, best.payload_bits);
    *payload_bits_out = best.payload_bits;
    if(errors_out) *errors_out = best.errors;
    if(leading_run_out) *leading_run_out = best.leading_run;
    if(low_bit_out) *low_bit_out = best.low_bit;
    if(invert_out) *invert_out = best.invert;
    if(align_out) *align_out = best.align;
    if(prefix_bits_out) *prefix_bits_out = best.prefix_bits;
    if(stats) {
        stats->tag_phase_locked++;
        if(best.prefix_bits > 0U) stats->tag_phase_prefix_restores++;
    }
    return true;
}

static uint32_t count_leading_ones(const uint8_t* decoded, uint32_t decoded_count) {
    uint32_t n = 0;
    while(n < decoded_count && decoded[n] == 1U) {
        n++;
    }
    return n;
}

static bool try_decode_tag(
    const FrameBuffer* frame,
    uint8_t* payload,
    uint32_t* payload_bits_out,
    uint32_t* errors_out,
    uint32_t* leading_run_out,
    TagDropReason* drop_reason_out,
    DecodeStats* stats) {
    uint8_t nrz[MAX_FRAME_BITS * 2U];
    uint8_t decoded[MAX_FRAME_BITS];

    uint32_t best_payload_bits = 0;
    uint32_t best_errors = 1000U;
    uint32_t best_leading_run = 0;
    uint8_t best_payload[MAX_FRAME_BITS];
    bool saw_nrz = false;
    bool saw_manchester = false;
    bool saw_header = false;

    for(uint8_t low_bit = 0; low_bit < 2U; low_bit++) {
        uint32_t nrz_count = build_nrz(frame, low_bit, nrz, COUNT_OF(nrz));
        if(nrz_count < 16U) continue;
        saw_nrz = true;

        for(uint8_t invert = 0; invert < 2U; invert++) {
            for(uint8_t align = 0; align < 2U; align++) {
                uint32_t errors = 0;
                uint32_t decoded_count =
                    manchester_decode(nrz, nrz_count, invert, align, decoded, COUNT_OF(decoded), &errors);

                if(decoded_count < 13U || errors > 2U) continue;
                saw_manchester = true;

                bool header_ok = true;
                for(uint32_t i = 0; i < 5U; i++) {
                    if(decoded[i] != 1U) {
                        header_ok = false;
                        break;
                    }
                }
                if(!header_ok) continue;
                saw_header = true;

                uint32_t payload_bits = decoded_count - 5U;
                if(payload_bits < 8U) continue;

                uint32_t leading_run = count_leading_ones(decoded, decoded_count);
                bool guarded_run_promotion =
                    best_payload_bits > 0U && leading_run > best_leading_run &&
                    errors <= best_errors + 1U && payload_bits + 1U >= best_payload_bits;

                if(best_payload_bits == 0U || guarded_run_promotion || (errors < best_errors) ||
                   ((errors == best_errors) &&
                    ((payload_bits > best_payload_bits) ||
                     (payload_bits == best_payload_bits && leading_run > best_leading_run)))) {
                    if(guarded_run_promotion && stats) stats->tag_header_run_promotions++;
                    best_errors = errors;
                    best_leading_run = leading_run;
                    best_payload_bits = payload_bits;
                    memcpy(best_payload, decoded + 5U, payload_bits);
                }
            }
        }
    }

    if(best_payload_bits == 0U) {
        if(drop_reason_out) {
            if(!saw_nrz) {
                *drop_reason_out = TagDropNoNrz;
            } else if(!saw_manchester) {
                *drop_reason_out = TagDropNoManchester;
            } else if(!saw_header) {
                *drop_reason_out = TagDropNoHeader;
            } else {
                *drop_reason_out = TagDropPayloadShort;
            }
        }
        return false;
    }

    if(best_payload_bits < 16U) {
        if(drop_reason_out) *drop_reason_out = TagDropPayloadShort;
        return false;
    }

    bool all_zero = true;
    bool all_one = true;
    for(uint32_t i = 0; i < best_payload_bits; i++) {
        if(best_payload[i]) {
            all_zero = false;
        } else {
            all_one = false;
        }
    }
    if(all_zero || all_one) {
        if(drop_reason_out) *drop_reason_out = TagDropAllSame;
        return false;
    }

    memcpy(payload, best_payload, best_payload_bits);
    *payload_bits_out = best_payload_bits;
    if(errors_out) *errors_out = best_errors;
    if(leading_run_out) *leading_run_out = best_leading_run;
    if(drop_reason_out) *drop_reason_out = TagDropNone;
    return true;
}

static bool bits_all_same(const uint8_t* bits, uint32_t bit_count) {
    if(bit_count == 0U) return true;

    bool all_zero = true;
    bool all_one = true;
    for(uint32_t i = 0; i < bit_count; i++) {
        if(bits[i]) {
            all_zero = false;
        } else {
            all_one = false;
        }
    }

    return all_zero || all_one;
}

static bool decoded_has_hitag_header(const uint8_t* decoded, uint32_t decoded_count, uint32_t offset) {
    if(offset + 5U > decoded_count) return false;
    for(uint32_t i = 0; i < 5U; i++) {
        if(decoded[offset + i] != 1U) return false;
    }
    return true;
}

static bool try_decode_tag_adaptive(
    const FrameBuffer* frame,
    uint8_t* payload,
    uint32_t* payload_bits_out,
    uint32_t* errors_out,
    uint32_t* header_offset_out,
    uint32_t* leading_run_out,
    DecodeStats* stats) {
    uint8_t nrz[MAX_FRAME_BITS * 2U];
    uint8_t decoded[MAX_FRAME_BITS];
    uint8_t best_payload[MAX_FRAME_BITS];

    uint32_t best_score = UINT32_MAX;
    uint32_t best_payload_bits = 0;
    uint32_t best_errors = 0;
    uint32_t best_header_offset = 0;
    uint32_t best_leading_run = 0;

    if(stats) stats->tag_adaptive_attempts++;

    for(uint8_t low_bit = 0; low_bit < 2U; low_bit++) {
        uint32_t nrz_count = build_nrz(frame, low_bit, nrz, COUNT_OF(nrz));
        if(nrz_count < 16U) continue;

        for(uint8_t invert = 0; invert < 2U; invert++) {
            for(uint8_t align = 0; align < 2U; align++) {
                uint32_t errors = 0;
                uint32_t decoded_count =
                    manchester_decode(nrz, nrz_count, invert, align, decoded, COUNT_OF(decoded), &errors);
                if(decoded_count < 21U || errors > 12U) continue;

                uint32_t max_header_offset = decoded_count > 24U ? 16U : 4U;
                for(uint32_t header_offset = 0; header_offset <= max_header_offset; header_offset++) {
                    if(!decoded_has_hitag_header(decoded, decoded_count, header_offset)) continue;

                    uint32_t payload_start = header_offset + 5U;
                    uint32_t payload_bits = decoded_count - payload_start;
                    if(payload_bits < 16U) continue;
                    if(payload_bits > MAX_FRAME_BITS) payload_bits = MAX_FRAME_BITS;
                    if(bits_all_same(decoded + payload_start, payload_bits)) continue;

                    char paxton[32];
                    uint32_t digits = 0;
                    bool paxton_ok =
                        paxton_digits_from_bits(decoded + payload_start, payload_bits, paxton, sizeof(paxton), &digits);

                    uint32_t score = (errors * 32U) + (header_offset * 4U);
                    if(paxton_ok && digits >= 3U) {
                        score = score > 64U ? score - 64U : 0U;
                    }
                    if(payload_bits >= 32U) {
                        score = score > 16U ? score - 16U : 0U;
                    }

                    uint32_t leading_run =
                        count_leading_ones(decoded + header_offset, decoded_count - header_offset);
                    bool guarded_run_promotion =
                        best_payload_bits > 0U && leading_run > best_leading_run &&
                        errors <= best_errors + 1U && payload_bits + 1U >= best_payload_bits;

                    if(best_payload_bits == 0U || guarded_run_promotion || score < best_score ||
                       (score == best_score && payload_bits > best_payload_bits)) {
                        if(guarded_run_promotion && stats) stats->tag_header_run_promotions++;
                        best_score = score;
                        best_payload_bits = payload_bits;
                        best_errors = errors;
                        best_header_offset = header_offset;
                        best_leading_run = leading_run;
                        memcpy(best_payload, decoded + payload_start, payload_bits);
                    }
                }
            }
        }
    }

    if(best_payload_bits == 0U) {
        return false;
    }

    memcpy(payload, best_payload, best_payload_bits);
    *payload_bits_out = best_payload_bits;
    if(errors_out) *errors_out = best_errors;
    if(header_offset_out) *header_offset_out = best_header_offset;
    if(leading_run_out) *leading_run_out = best_leading_run;
    if(stats) stats->tag_adaptive_frames++;
    return true;
}

static void reset_frame(FrameBuffer* frame) {
    frame->count = 0;
}

static void reset_builder(SegmentBuilder* builder) {
    memset(builder, 0, sizeof(*builder));
}

static bool frame_has_useful_segments(const FrameBuffer* frame) {
    if(frame->count < 2U) return false;
    for(uint32_t i = 0; i < frame->count; i++) {
        if(frame->seg[i].duration_us >= 24U && frame->seg[i].duration_us <= 320U) {
            return true;
        }
    }
    return false;
}

/*
 * V11.10: reference bit pattern for the known password BDF5E846, used for a
 * tolerant match below. Three independent sessions this round produced a
 * 32-bit reader frame exactly one bit away from this pattern (3DF5E846,
 * B5F5E846, ADF5E846), always logged as UNK because reader_bits_are_protocol_
 * command() required an exact hex match. An UNK password frame does not open
 * a tag window, so any genuine tag reply that would have followed it is
 * silently missed -- not mis-decoded, just never given a window to be
 * decoded in.
 */
static const uint8_t HT2_PASSWORD_BITS[32] = {
    1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1,
    1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
};

static bool bits_hamming_distance_le1(
    const uint8_t* bits,
    const uint8_t* reference,
    uint32_t count) {
    uint32_t mismatches = 0;
    for(uint32_t i = 0; i < count; i++) {
        if(bits[i] != reference[i]) {
            mismatches++;
            if(mismatches > 1U) return false;
        }
    }
    return true;
}

static bool reader_bits_are_protocol_command(
    const uint8_t* bits,
    uint32_t bit_count,
    const char* bit_string,
    const char* hex,
    bool* fuzzy_out) {
    if(fuzzy_out) *fuzzy_out = false;

    if(bit_count == 5U) {
        return memcmp(bit_string, "11000", 5U) == 0;
    }

    if(bit_count == 10U) {
        return (memcmp(bit_string, "1110000011", 10U) == 0) ||
               (memcmp(bit_string, "1110100010", 10U) == 0) ||
               (memcmp(bit_string, "1111000001", 10U) == 0) ||
               (memcmp(bit_string, "1111100000", 10U) == 0);
    }

    if(bit_count == 32U) {
        if(strcmp(hex, "BDF5E846") == 0) {
            return true;
        }
        /* Single-bit-flip tolerance only -- 1 bit out of 2^32 possible
         * values is an astronomically tight false-positive bound, so this
         * stays conservative while recovering the observed corruption
         * pattern. */
        if(bits_hamming_distance_le1(bits, HT2_PASSWORD_BITS, 32U)) {
            if(fuzzy_out) *fuzzy_out = true;
            return true;
        }
    }

    return false;
}

static void append_segment_to_frame(FrameBuffer* frame, const Segment* segment) {
    if(frame->count < MAX_FRAME_SEGMENTS) {
        frame->seg[frame->count++] = *segment;
    } else {
        reset_frame(frame);
    }
}

/*
 * V12: short label for a recognized reader command, used to tag every tag
 * reply with the command that opened its window (after=...). Only called
 * when reader_bits_are_protocol_command() already returned true, so the
 * "CMD?" fallback should not normally be reachable -- it's a safety net,
 * not an expected case.
 */
static const char* reader_command_label(
    bool start_auth,
    uint32_t bit_count,
    const char* hex,
    bool fuzzy_password) {
    if(start_auth) return "START_AUTH";
    if(bit_count == 32U) return fuzzy_password ? "BDF5E846~1b" : "BDF5E846";
    if(bit_count == 10U) {
        if(strcmp(hex, "E0") == 0) return "E0";
        if(strcmp(hex, "E8") == 0) return "E8";
        if(strcmp(hex, "F0") == 0) return "F0";
        if(strcmp(hex, "F8") == 0) return "F8";
    }
    return "CMD?";
}

static void close_tag_window(
    SegmentBuilder* tag_builder,
    FrameBuffer* tag_frame,
    File* file,
    uint32_t last_reader_us,
    const char* last_reader_label,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats);

static bool log_reader_frame(
    File* file,
    const FrameBuffer* frame,
    uint32_t* last_reader_us,
    uint32_t* reader_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    if(!frame_has_useful_segments(frame)) {
        return false;
    }

    uint8_t bits[MAX_FRAME_BITS];
    uint32_t bit_count = 0;
    char bit_string[128];
    char hex[64];
    char line[MAX_LINE];

    uint32_t start_us = frame->seg[0].start_us;
    uint32_t end_us = frame->seg[frame->count - 1U].start_us + frame->seg[frame->count - 1U].duration_us;

    bool adaptive = false;
    uint32_t adaptive_score = 0;
    if(try_decode_reader(frame, bits, &bit_count) ||
       (adaptive = try_decode_reader_adaptive(frame, bits, &bit_count, &adaptive_score, stats))) {
        bits_to_string(bits, bit_count, bit_string, sizeof(bit_string));
        bits_to_hex(bits, bit_count, hex, sizeof(hex));
        bool start_auth = (bit_count == 5U && memcmp(bit_string, "11000", 5U) == 0);
        bool fuzzy_password = false;
        bool protocol_command =
            reader_bits_are_protocol_command(bits, bit_count, bit_string, hex, &fuzzy_password);
        if(adaptive) {
            if(stats) stats->reader_adaptive_frames++;
            snprintf(
                line,
                sizeof(line),
                "R t=%lu.%03lums bits=%lu hex=%s%s%s%s ADAPT score=%lu raw=%s\n",
                (unsigned long)(start_us / 1000U),
                (unsigned long)(start_us % 1000U),
                (unsigned long)bit_count,
                hex,
                start_auth ? " START_AUTH" : "",
                protocol_command ? "" : " UNK",
                fuzzy_password ? " FUZZY" : "",
                (unsigned long)adaptive_score,
                bit_string);
        } else {
            snprintf(
                line,
                sizeof(line),
                "R t=%lu.%03lums bits=%lu hex=%s%s%s%s raw=%s\n",
                (unsigned long)(start_us / 1000U),
                (unsigned long)(start_us % 1000U),
                (unsigned long)bit_count,
                hex,
                start_auth ? " START_AUTH" : "",
                protocol_command ? "" : " UNK",
                fuzzy_password ? " FUZZY" : "",
                bit_string);
        }
        write_line(file, line);
        if(protocol_command && last_reader_us) {
            *last_reader_us = end_us;
            g_last_reader_label = reader_command_label(start_auth, bit_count, hex, fuzzy_password);
            arm_page_capture(g_last_reader_label, end_us);
        }
        if(reader_frames) (*reader_frames)++;
        if(!protocol_command && stats) stats->reader_unrecognized++;
        if(fuzzy_password && stats) stats->reader_password_fuzzy_accepts++;
        return protocol_command;
    }

    if(end_us > start_us) {
        if(invalid_frames) (*invalid_frames)++;
        if(stats) {
            stats->reader_invalid++;
            uint32_t diag_bits = 0;
            (void)try_decode_reader_diag(frame, bits, &diag_bits, stats);
        }
    }

    return false;
}

static void log_tag_diag(
    File* file,
    const FrameBuffer* frame,
    uint32_t last_reader_us,
    const char* last_reader_label,
    TagDropReason reason,
    DecodeStats* stats) {
    if(!stats || stats->tag_diag_lines >= TAG_DIAG_LIMIT || frame->count == 0U) return;

    char line[MAX_LINE];
    size_t pos = 0;
    uint32_t start_us = frame->seg[0].start_us;
    uint32_t dt_us =
        (last_reader_us != UINT32_MAX && start_us >= last_reader_us) ? start_us - last_reader_us : 0U;
    int written = snprintf(
        line,
        sizeof(line),
        "T_DIAG after=%s dtR=%luus reason=%u seg=",
        last_reader_label,
        (unsigned long)dt_us,
        (unsigned int)reason);
    if(written < 0) return;
    pos = (size_t)written < sizeof(line) ? (size_t)written : sizeof(line) - 1U;

    uint32_t segment_limit = frame->count < 16U ? frame->count : 16U;
    for(uint32_t i = 0; i < segment_limit && pos + 16U < sizeof(line); i++) {
        written = snprintf(
            line + pos,
            sizeof(line) - pos,
            "%c%lu",
            frame->seg[i].low ? 'L' : 'H',
            (unsigned long)frame->seg[i].duration_us);
        if(written < 0) break;
        pos += (size_t)written;
    }

    uint8_t nrz[MAX_FRAME_BITS * 2U];
    uint32_t nrz_count = build_nrz(frame, 0U, nrz, COUNT_OF(nrz));
    if(pos + 7U < sizeof(line)) {
        written = snprintf(line + pos, sizeof(line) - pos, " nrz0=");
        if(written > 0) pos += (size_t)written;
    }
    uint32_t nrz_limit = nrz_count < 80U ? nrz_count : 80U;
    for(uint32_t i = 0; i < nrz_limit && pos + 2U < sizeof(line); i++) {
        line[pos++] = nrz[i] ? '1' : '0';
    }
    if(pos + 2U < sizeof(line)) line[pos++] = '\n';
    line[pos] = '\0';
    write_line(file, line);
    stats->tag_diag_lines++;
}

static void log_tag_frame(
    File* file,
    const FrameBuffer* frame,
    uint32_t last_reader_us,
    const char* last_reader_label,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    if(!frame_has_useful_segments(frame)) {
        return;
    }

    uint8_t bits[MAX_FRAME_BITS];
    uint32_t bit_count = 0;
    char bit_string[128];
    char hex[64];
    char line[MAX_LINE];

    uint32_t start_us = frame->seg[0].start_us;
    uint32_t end_us = frame->seg[frame->count - 1U].start_us + frame->seg[frame->count - 1U].duration_us;
    update_tag_segment_stats(frame, stats);

    uint32_t errors = 0;
    TagDropReason drop_reason = TagDropNone;
    bool phase_locked = false;
    bool adaptive = false;
    uint32_t header_offset = 0;
    uint32_t leading_run = 0;
    uint8_t phase_low_bit = 0;
    uint8_t phase_invert = 0;
    uint8_t phase_align = 0;
    uint8_t phase_prefix = 0;
    bool phase_window = last_reader_us != UINT32_MAX && start_us >= last_reader_us &&
                        start_us - last_reader_us >= TAG_PHASE_DT_MIN_US &&
                        start_us - last_reader_us <= TAG_PHASE_DT_MAX_US;
    if((phase_locked = phase_window && try_decode_tag_phase_locked(
            frame,
            bits,
            &bit_count,
            &errors,
            &leading_run,
            &phase_low_bit,
            &phase_invert,
            &phase_align,
            &phase_prefix,
            stats)) ||
       try_decode_tag(frame, bits, &bit_count, &errors, &leading_run, &drop_reason, stats) ||
       (adaptive = try_decode_tag_adaptive(
            frame, bits, &bit_count, &errors, &header_offset, &leading_run, stats))) {
        bits_to_string(bits, bit_count, bit_string, sizeof(bit_string));
        bits_to_hex(bits, bit_count, hex, sizeof(hex));

        char paxton[32];
        uint32_t digits = 0;
        bool paxton_ok = paxton_digits_from_bits(bits, bit_count, paxton, sizeof(paxton), &digits);

        /*
         * V12: separate "is there reader context, and is it a sane delay"
         * from the display string, so the same numbers can drive the
         * T_STRONG/T_WEAK verdict (Gepeto's proposal, V11.9b analysis
         * session): strong requires <=2 Manchester errors AND a
         * non-negative, sub-25ms delay since the last recognized command.
         * 25ms is generous on purpose -- every confirmed-clean recurring
         * block this round (FF49F8/F3FF50/EC0000/20DF07) sat at ~1.7-7.7ms,
         * so this only excludes the genuinely late/ambiguous tail.
         */
        bool dt_known = (last_reader_us != UINT32_MAX);
        bool dt_negative = dt_known && (start_us < last_reader_us);
        uint32_t dt_us = 0;
        if(dt_known) {
            dt_us = dt_negative ? (last_reader_us - start_us) : (start_us - last_reader_us);
        }
        bool strong = dt_known && !dt_negative && (dt_us <= 25000U) && (errors <= 2U);
        if(phase_locked && phase_window && paxton_ok) {
            observe_direct_page(
                last_reader_label,
                bits,
                bit_count,
                errors,
                phase_locked,
                last_reader_us,
                paxton_ok,
                paxton);
        }

        char dt_reader[24];
        if(!dt_known) {
            snprintf(dt_reader, sizeof(dt_reader), "NA");
        } else if(dt_negative) {
            snprintf(
                dt_reader,
                sizeof(dt_reader),
                "-%lu.%03lums",
                (unsigned long)(dt_us / 1000U),
                (unsigned long)(dt_us % 1000U));
        } else {
            snprintf(
                dt_reader,
                sizeof(dt_reader),
                "%lu.%03lums",
                (unsigned long)(dt_us / 1000U),
                (unsigned long)(dt_us % 1000U));
        }

        if(phase_locked) {
            snprintf(
                line,
                sizeof(line),
                "%s after=%s t=%lu.%03lums bits=%lu err=%lu run=%lu hex=%s%s%s%s dtR=%s PHASE lb=%u inv=%u align=%u pre=%u raw=%s\n",
                strong ? "T_STRONG" : "T_WEAK",
                last_reader_label,
                (unsigned long)(start_us / 1000U),
                (unsigned long)(start_us % 1000U),
                (unsigned long)bit_count,
                (unsigned long)errors,
                (unsigned long)leading_run,
                hex,
                paxton_ok ? " paxton=" : "",
                paxton_ok ? paxton : "",
                (paxton_ok && digits >= 6U) ? " PAXTON5" : "",
                dt_reader,
                (unsigned int)phase_low_bit,
                (unsigned int)phase_invert,
                (unsigned int)phase_align,
                (unsigned int)phase_prefix,
                bit_string);
        } else if(adaptive) {
            snprintf(
                line,
                sizeof(line),
                "%s after=%s t=%lu.%03lums bits=%lu err=%lu run=%lu hex=%s%s%s%s dtR=%s ADAPT hdr=%lu raw=%s\n",
                strong ? "T_STRONG" : "T_WEAK",
                last_reader_label,
                (unsigned long)(start_us / 1000U),
                (unsigned long)(start_us % 1000U),
                (unsigned long)bit_count,
                (unsigned long)errors,
                (unsigned long)leading_run,
                hex,
                paxton_ok ? " paxton=" : "",
                paxton_ok ? paxton : "",
                (paxton_ok && digits >= 6U) ? " PAXTON5" : "",
                dt_reader,
                (unsigned long)header_offset,
                bit_string);
        } else {
            snprintf(
                line,
                sizeof(line),
                "%s after=%s t=%lu.%03lums bits=%lu err=%lu run=%lu hex=%s%s%s%s dtR=%s raw=%s\n",
                strong ? "T_STRONG" : "T_WEAK",
                last_reader_label,
                (unsigned long)(start_us / 1000U),
                (unsigned long)(start_us % 1000U),
                (unsigned long)bit_count,
                (unsigned long)errors,
                (unsigned long)leading_run,
                hex,
                paxton_ok ? " paxton=" : "",
                paxton_ok ? paxton : "",
                (paxton_ok && digits >= 6U) ? " PAXTON5" : "",
                dt_reader,
                bit_string);
        }
        write_line(file, line);
        if (tag_frames) (*tag_frames)++;
        if(stats) {
            if(strong) {
                stats->tag_strong++;
            } else {
                stats->tag_weak++;
            }
        }
        return;
    }

    if(end_us > start_us) {
        log_tag_diag(file, frame, last_reader_us, last_reader_label, drop_reason, stats);
        if (invalid_frames) (*invalid_frames)++;
        if(stats) {
            stats->tag_invalid++;
            switch(drop_reason) {
            case TagDropNoNrz:
                stats->tag_drop_no_nrz++;
                break;
            case TagDropNoManchester:
                stats->tag_drop_no_manchester++;
                break;
            case TagDropNoHeader:
                stats->tag_drop_no_header++;
                break;
            case TagDropPayloadShort:
                stats->tag_drop_payload_short++;
                break;
            case TagDropAllSame:
                stats->tag_drop_all_same++;
                break;
            case TagDropNone:
            default:
                break;
            }
        }
    }
}

static void finalize_segment(
    const SegmentBuilder* builder,
    FrameBuffer* frame,
    SegmentBuilder* tag_builder,
    FrameBuffer* tag_frame,
    File* file,
    uint32_t* last_reader_us,
    uint32_t* reader_frames,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    if(!builder->has_state || builder->blocks == 0U) {
        return;
    }

    Segment segment = {
        .low = builder->state_low,
        .start_us = builder->start_us,
        .duration_us = builder->duration_us,
        .mean_v = (uint16_t)(builder->mean_sum / builder->blocks),
        .min_v = builder->min_v,
        .max_v = builder->max_v,
    };

    if(segment.duration_us >= HT2_LONG_GAP_US) {
        uint32_t previous_reader_us = last_reader_us ? *last_reader_us : UINT32_MAX;
        const char* previous_reader_label = g_last_reader_label;
        bool decoded_reader =
            log_reader_frame(file, frame, last_reader_us, reader_frames, invalid_frames, stats);
        if(decoded_reader) {
            close_tag_window(
                tag_builder,
                tag_frame,
                file,
                previous_reader_us,
                previous_reader_label,
                tag_frames,
                invalid_frames,
                stats);
        }
        reset_frame(frame);
    } else if(!segment.low && segment.duration_us >= HT2_READER_STOP_MIN_US &&
              frame_decodes_as_reader(frame)) {
        uint32_t previous_reader_us = last_reader_us ? *last_reader_us : UINT32_MAX;
        const char* previous_reader_label = g_last_reader_label;
        bool decoded_reader =
            log_reader_frame(file, frame, last_reader_us, reader_frames, invalid_frames, stats);
        if(decoded_reader) {
            close_tag_window(
                tag_builder,
                tag_frame,
                file,
                previous_reader_us,
                previous_reader_label,
                tag_frames,
                invalid_frames,
                stats);
        }
        reset_frame(frame);
    } else if(segment.duration_us >= 24U) {
        append_segment_to_frame(frame, &segment);
    }
}

static void finalize_tag_segment(
    const SegmentBuilder* builder,
    FrameBuffer* frame,
    File* file,
    uint32_t last_reader_us,
    const char* last_reader_label,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    if(!builder->has_state || builder->blocks == 0U) {
        return;
    }

    Segment segment = {
        .low = builder->state_low,
        .start_us = builder->start_us,
        .duration_us = builder->duration_us,
        .mean_v = (uint16_t)(builder->mean_sum / builder->blocks),
        .min_v = builder->min_v,
        .max_v = builder->max_v,
    };

    if(segment.duration_us >= HT2_LONG_GAP_US) {
        log_tag_frame(file, frame, last_reader_us, last_reader_label, tag_frames, invalid_frames, stats);
        reset_frame(frame);
    } else if(segment.duration_us >= 24U) {
        append_segment_to_frame(frame, &segment);
    }
}

static void close_tag_window(
    SegmentBuilder* tag_builder,
    FrameBuffer* tag_frame,
    File* file,
    uint32_t last_reader_us,
    const char* last_reader_label,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    finalize_tag_segment(
        tag_builder, tag_frame, file, last_reader_us, last_reader_label, tag_frames, invalid_frames, stats);
    log_tag_frame(file, tag_frame, last_reader_us, last_reader_label, tag_frames, invalid_frames, stats);
    reset_builder(tag_builder);
    reset_frame(tag_frame);
}

static void update_levels(EnvelopeLevels* levels, uint16_t block_min, uint16_t block_max) {
    uint32_t span = (block_max > block_min) ? (uint32_t)(block_max - block_min) : 0U;
    if(span < 500U) {
        if(!levels->initialized) {
            levels->low_level = block_min;
            levels->high_level = block_max;
            levels->threshold = (uint16_t)(((uint32_t)block_min + block_max) / 2U);
        }
        return;
    }

    if(!levels->initialized) {
        levels->low_level = block_min;
        levels->high_level = block_max;
        levels->initialized = true;
    } else {
        levels->low_level = (uint16_t)(((uint32_t)levels->low_level * 7U + block_min) / 8U);
        levels->high_level = (uint16_t)(((uint32_t)levels->high_level * 7U + block_max) / 8U);
    }

    levels->threshold =
        (uint16_t)((uint32_t)levels->low_level + (((uint32_t)levels->high_level - levels->low_level) / 2U));
}

static void feed_block_mean(
    SegmentBuilder* builder,
    FrameBuffer* frame,
    SegmentBuilder* tag_builder,
    FrameBuffer* tag_frame,
    File* file,
    uint32_t time_us,
    uint16_t mean,
    uint16_t threshold,
    uint32_t* last_reader_us,
    uint32_t* reader_frames,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    bool low = mean < threshold;

    if(!builder->has_state) {
        builder->has_state = true;
        builder->state_low = low;
        builder->start_us = time_us;
        builder->duration_us = BLOCK_US;
        builder->mean_sum = mean;
        builder->blocks = 1U;
        builder->min_v = mean;
        builder->max_v = mean;
        return;
    }

    if(low == builder->state_low) {
        builder->duration_us += BLOCK_US;
        builder->mean_sum += mean;
        builder->blocks++;
        if(mean < builder->min_v) builder->min_v = mean;
        if(mean > builder->max_v) builder->max_v = mean;
        return;
    }

    finalize_segment(
        builder,
        frame,
        tag_builder,
        tag_frame,
        file,
        last_reader_us,
        reader_frames,
        tag_frames,
        invalid_frames,
        stats);

    builder->state_low = low;
    builder->start_us = time_us;
    builder->duration_us = BLOCK_US;
    builder->mean_sum = mean;
    builder->blocks = 1U;
    builder->min_v = mean;
    builder->max_v = mean;
}

static void feed_tag_ac_block(
    TagAcState* ac,
    SegmentBuilder* builder,
    FrameBuffer* frame,
    File* file,
    uint32_t time_us,
    uint16_t mean,
    bool skip_for_reader_low,
    uint32_t last_reader_us,
    const char* last_reader_label,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    if(last_reader_us == UINT32_MAX) {
        if(stats) stats->tag_wait_reader_skips++;
        return;
    }

    if(time_us - last_reader_us > TAG_RESPONSE_MAX_US) {
        if(builder->has_state || frame->count > 0U) {
            if(stats) stats->tag_window_timeouts++;
            reset_builder(builder);
            reset_frame(frame);
        }
        return;
    }

    if(skip_for_reader_low) {
        if(stats) stats->tag_reader_low_skips++;
        return;
    }

    int32_t mean_q8 = (int32_t)mean << 8;
    if(!ac->initialized) {
        ac->initialized = true;
        ac->dc_q8 = mean_q8;
        ac->abs_q8 = 0U;
    }

    int32_t residual_q8 = mean_q8 - ac->dc_q8;
    uint32_t abs_q8 = (residual_q8 < 0) ? (uint32_t)(-residual_q8) : (uint32_t)residual_q8;
    ac->dc_q8 += (mean_q8 - ac->dc_q8) >> TAG_AC_DC_SHIFT;
    int32_t abs_delta_q8 = (int32_t)abs_q8 - (int32_t)ac->abs_q8;
    ac->abs_q8 = (uint32_t)((int32_t)ac->abs_q8 + (abs_delta_q8 >> TAG_AC_ABS_SHIFT));

    if(ac->abs_q8 < TAG_AC_MIN_ABS_Q8 && !builder->has_state) {
        return;
    }

    uint32_t hysteresis_q8 = ac->abs_q8 >> 2;
    if(hysteresis_q8 < TAG_AC_HYST_MIN_Q8) hysteresis_q8 = TAG_AC_HYST_MIN_Q8;

    bool low = residual_q8 < 0;
    if(builder->has_state) {
        /* Keep uncertain residuals in the current state. A one-count sign
         * flip is evidence with low confidence, not a Manchester edge. */
        if(builder->state_low) {
            low = residual_q8 <= (int32_t)hysteresis_q8;
        } else {
            low = residual_q8 < -(int32_t)hysteresis_q8;
        }
    }
    uint16_t pseudo_mean = (uint16_t)((residual_q8 + 32768) < 0 ? 0 :
                                      ((residual_q8 + 32768) > 65535 ? 65535 :
                                                                        (residual_q8 + 32768)));

    if(!builder->has_state) {
        builder->has_state = true;
        builder->state_low = low;
        builder->start_us = time_us;
        builder->duration_us = BLOCK_US;
        builder->mean_sum = pseudo_mean;
        builder->blocks = 1U;
        builder->min_v = pseudo_mean;
        builder->max_v = pseudo_mean;
        return;
    }

    if(low == builder->state_low) {
        /*
         * V11.9: duration_us must track true elapsed wall-clock time, not the
         * number of *processed* blocks. skip_for_reader_low returns early
         * above on every block where the reader is pulling the line low, and
         * that happens tens of thousands of times per session (see
         * tag_reader_low_skips). A plain "+= BLOCK_US" silently undercounts
         * any tag segment that straddles one of those skipped blocks, which
         * then feeds a wrong duration into segment_to_nrz_count() and
         * desyncs the downstream Manchester bitstream. Recomputing from
         * (time_us - start_us) is immune to however many blocks were skipped
         * in between, as long as we treat the state as having persisted
         * through the gap (which is the same assumption skip_for_reader_low
         * already makes).
         */
        builder->duration_us = (uint32_t)(time_us - builder->start_us) + BLOCK_US;
        builder->mean_sum += pseudo_mean;
        builder->blocks++;
        if(pseudo_mean < builder->min_v) builder->min_v = pseudo_mean;
        if(pseudo_mean > builder->max_v) builder->max_v = pseudo_mean;

        if(builder->duration_us >= HT2_LONG_GAP_US) {
            finalize_tag_segment(
                builder, frame, file, last_reader_us, last_reader_label, tag_frames, invalid_frames, stats);
            reset_builder(builder);
        }
        return;
    }

    finalize_tag_segment(
        builder, frame, file, last_reader_us, last_reader_label, tag_frames, invalid_frames, stats);

    builder->state_low = low;
    builder->start_us = time_us;
    builder->duration_us = BLOCK_US;
    builder->mean_sum = pseudo_mean;
    builder->blocks = 1U;
    builder->min_v = pseudo_mean;
    builder->max_v = pseudo_mean;
}

static uint16_t tag_envelope_smooth(TagAcState* ac, uint16_t envelope) {
    if(ac->envelope_count < COUNT_OF(ac->envelope_history)) {
        ac->envelope_history[ac->envelope_pos] = envelope;
        ac->envelope_sum += envelope;
        ac->envelope_count++;
    } else {
        ac->envelope_sum -= ac->envelope_history[ac->envelope_pos];
        ac->envelope_history[ac->envelope_pos] = envelope;
        ac->envelope_sum += envelope;
    }

    ac->envelope_pos =
        (uint8_t)((ac->envelope_pos + 1U) % COUNT_OF(ac->envelope_history));
    return (uint16_t)(ac->envelope_sum / ac->envelope_count);
}

static void process_half(
    const uint16_t* samples,
    uint64_t sample_abs_start,
    EnvelopeLevels* reader_levels,
    TagAcState* tag_ac,
    SegmentBuilder* reader_builder,
    FrameBuffer* reader_frame,
    SegmentBuilder* tag_builder,
    FrameBuffer* tag_frame,
    File* file,
    uint32_t* last_reader_us,
    uint32_t* reader_frames,
    uint32_t* tag_frames,
    uint32_t* invalid_frames,
    DecodeStats* stats) {
    uint16_t block_min = 0xFFFFU;
    uint16_t block_max = 0U;

    for(uint32_t i = 0; i < COUNT_OF(block_means); i++) {
        uint32_t sum = 0;
        for(uint32_t j = 0; j < BLOCK_SAMPLES; j++) {
            sum += samples[i * BLOCK_SAMPLES + j];
        }
        uint16_t mean = (uint16_t)(sum / BLOCK_SAMPLES);
        block_means[i] = mean;

        if(mean < block_min) block_min = mean;
        if(mean > block_max) block_max = mean;
    }

    update_levels(reader_levels, block_min, block_max);
    bool reader_ready =
        reader_levels->initialized &&
        ((uint32_t)reader_levels->high_level - (uint32_t)reader_levels->low_level) >= 800U;

    if(!reader_ready) {
        if((reader_builder->has_state || reader_frame->count > 0U) && stats) {
            stats->reader_gate_resets++;
        }
        reset_builder(reader_builder);
        reset_frame(reader_frame);
    }

    for(uint32_t i = 0; i < COUNT_OF(block_means); i++) {
        uint32_t time_us =
            (uint32_t)((sample_abs_start + (uint64_t)i * BLOCK_SAMPLES) * ADC_SAMPLE_US);
        bool reader_low = reader_ready && (block_means[i] < reader_levels->threshold);

        if(reader_ready) {
            feed_block_mean(
                reader_builder,
                reader_frame,
                tag_builder,
                tag_frame,
                file,
                time_us,
                block_means[i],
                reader_levels->threshold,
                last_reader_us,
                reader_frames,
                tag_frames,
                invalid_frames,
                stats);
        }

        if(*last_reader_us == UINT32_MAX) {
            if(stats) stats->tag_wait_reader_skips++;
            continue;
        }

        uint16_t tag_envelope = 0U;
        if(!reader_low && time_us - *last_reader_us <= TAG_RESPONSE_MAX_US) {
            uint32_t deviation_sum = 0U;
            for(uint32_t j = 0; j < BLOCK_SAMPLES; j++) {
                int32_t deviation =
                    (int32_t)samples[i * BLOCK_SAMPLES + j] - block_means[i];
                deviation_sum += (uint32_t)(deviation < 0 ? -deviation : deviation);
            }
            tag_envelope =
                tag_envelope_smooth(tag_ac, (uint16_t)(deviation_sum / BLOCK_SAMPLES));
        }

        feed_tag_ac_block(
            tag_ac,
            tag_builder,
            tag_frame,
            file,
            time_us,
            tag_envelope,
            reader_low,
            *last_reader_us,
            g_last_reader_label,
            tag_frames,
            invalid_frames,
            stats);
    }
}

int32_t hitag2_protocol_run(void* context) {
    UNUSED(context);

    FURI_LOG_I(TAG, "App start: Paxton Sniffer V1.0 on Unleashed 093");
    FURI_LOG_I(
        TAG,
        "No RF emission. V17-compatible RX pins; E0/E8 windows stay in RAM.");

    Storage* storage = furi_record_open(RECORD_STORAGE);
    FURI_LOG_I(TAG, "Storage opened");
    storage_common_mkdir(storage, CAPTURE_DIR);

    char log_path[96];
    uint32_t log_index = 0;
    if(!find_free_log_path(storage, log_path, sizeof(log_path), &log_index)) {
        furi_record_close(RECORD_STORAGE);
        FURI_LOG_E(TAG, "No free sniff slot found");
        return -1;
    }

    File* log_file = storage_file_alloc(storage);
    if(!storage_file_open(log_file, log_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(log_file);
        furi_record_close(RECORD_STORAGE);
        FURI_LOG_E(TAG, "Log open failed: %s", log_path);
        return -2;
    }
    FURI_LOG_I(TAG, "Log opened: %s", log_path);

    log_buffer_used = 0U;
    char line[MAX_LINE];
    write_line(
        log_file,
        "# Paxton Sniffer V1.0 direct and per-response SOF-edge consensus\n"
        "# firmware_base=unlshd-093 custom_api=88.11\n"
        "# antenna_state=V17_COMPAT RFID_PULL=1 RFID_OUT=0 no_flipper_rf=1\n"
        "# adc_scale_mv=2048 adc_sampling_cycles=6.5; requires custom U093 firmware\n"
        "# SOF clock fitted to first ten MAD edges; no unregistered page averaging\n");
    snprintf(
        line,
        sizeof(line),
        "# sample_rate_hz=%u block_us=%u mode=reader_context_filtered_tag_window\n"
        "# edge_capture start_dt_us=%u samples=%u max_repeats=%u baseband_window_us=%u baseband_step_us=%u metric=MAD\n"
        "# raw_page policy=first_complete_page_only_dump_on_stop\n",
        (unsigned int)SAMPLE_RATE_HZ,
        (unsigned int)BLOCK_US,
        (unsigned int)RAW_CAPTURE_START_DT_US,
        (unsigned int)RAW_CAPTURE_SAMPLES,
        (unsigned int)PAGE_CAPTURE_MAX_REPEATS,
        (unsigned int)(PAGE_BASEBAND_WINDOW_SAMPLES * 1000000U / SAMPLE_RATE_HZ),
        (unsigned int)(PAGE_BASEBAND_STEP_SAMPLES * 1000000U / SAMPLE_RATE_HZ));
    write_line(log_file, line);
    write_line(
        log_file,
        "# columns: R ... | T_STRONG/T_WEAK ... [PHASE lb inv align pre] raw | T_DIAG ...\n");

    memset(stream_buf, 0, sizeof(stream_buf));
    memset(raw_diagnostic_samples, 0, sizeof(raw_diagnostic_samples));
    memset(&raw_diagnostic_capture, 0, sizeof(raw_diagnostic_capture));
    memset(page_mad, 0, sizeof(page_mad));
    memset(page_accumulators, 0, sizeof(page_accumulators));
    memset(edge_valid_frames, 0, sizeof(edge_valid_frames));
    edge_event_total = 0U;
    memset(&page_capture_state, 0, sizeof(page_capture_state));
    memset(raw_history, 0, sizeof(raw_history));
    raw_history_start = 0U;
    raw_history_end = 0U;
    stream_completed_halves = 0U;
    stream_dropped_halves = 0U;
    stream_gap_events = 0U;
    stream_pending_peak = 0U;
    ui_reader_frames = 0U;
    memset(direct_pages, 0, sizeof(direct_pages));
    capture_ready = false;
    capture_active = false;
    captured_id = 0U;
    memset(captured_digits, 0, sizeof(captured_digits));

    memset(&reader_levels_state, 0, sizeof(reader_levels_state));
    memset(&tag_ac_state, 0, sizeof(tag_ac_state));
    memset(&reader_builder_state, 0, sizeof(reader_builder_state));
    memset(&reader_frame_state, 0, sizeof(reader_frame_state));
    memset(&tag_builder_state, 0, sizeof(tag_builder_state));
    memset(&tag_frame_state, 0, sizeof(tag_frame_state));
    memset(&decode_stats_state, 0, sizeof(decode_stats_state));
    g_last_reader_label = "NONE";
    uint32_t last_reader_us = UINT32_MAX;
    uint32_t reader_frames = 0;
    uint32_t tag_frames = 0;
    uint32_t invalid_frames = 0;
    uint16_t adc_min = UINT16_MAX;
    uint16_t adc_max = 0U;
    uint32_t adc_clip_low = 0U;
    uint32_t adc_clip_high = 0U;

    Hitag2Ui ui = {
        .input_queue = furi_message_queue_alloc(8, sizeof(InputEvent)),
    };

    ViewPort* view_port = view_port_alloc();
    view_port_draw_callback_set(view_port, draw_callback, &ui);
    view_port_input_callback_set(view_port, input_callback, &ui);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, view_port, GuiLayerFullscreen);
    FURI_LOG_I(TAG, "GUI ready");

    FURI_LOG_I(TAG, "Starting V17-compatible passive ADC DMA stream");
    capture_active = true;
    furi_hal_rfid_adc_dma_stream_start(
        stream_buf, STREAM_SAMPLES, SAMPLE_RATE_HZ, stream_callback, NULL);
    FURI_LOG_I(TAG, "ADC DMA stream started");

    uint32_t last_sequence = 0U;
    uint32_t processed_halves = 0U;
    uint32_t start_tick = furi_get_tick();
    uint32_t last_log_tick = start_tick;
    uint32_t last_gui_tick = start_tick;

    while(true) {
        if(capture_ready) break;
        if(should_abort_from_input(ui.input_queue)) {
            FURI_LOG_I(TAG, "User stop");
            break;
        }

        uint32_t gui_tick = furi_get_tick();
        if(gui_tick - last_gui_tick >= 500U) {
            last_gui_tick = gui_tick;
            view_port_update(view_port);
        }

        uint32_t sequence;
        if(!copy_latest_stream_half(last_sequence, &sequence)) {
            uint32_t now = furi_get_tick();
            if(now - last_log_tick >= 5000U) {
                last_log_tick = now;
                FURI_LOG_I(
                    TAG,
                    "Sniffing: R=%lu T=%lu invalid=%lu pages=%u/%u edge=%u/%u thr=%u",
                    (unsigned long)reader_frames,
                    (unsigned long)tag_frames,
                    (unsigned long)invalid_frames,
                    page_accumulators[0].captures,
                    page_accumulators[1].captures,
                    edge_valid_frames[0],
                    edge_valid_frames[1],
                    (unsigned int)reader_levels_state.threshold);
            }
            furi_delay_ms(1);
            continue;
        }

        uint32_t pending = sequence - last_sequence;
        if(pending > stream_pending_peak) stream_pending_peak = pending;
        uint64_t block_abs_start = (uint64_t)(sequence - 1U) * STREAM_HALF_SAMPLES;
        if(pending > 1U) {
            stream_dropped_halves += pending - 1U;
            stream_gap_events++;
            if(page_capture_state.armed) abort_page_capture_for_history_loss();
            if(raw_diagnostic_capture.armed) {
                raw_diagnostic_capture.armed = false;
                raw_diagnostic_capture.copied = 0U;
            }
            raw_history_start = block_abs_start;
            raw_history_end = block_abs_start;
            reset_builder(&reader_builder_state);
            reset_frame(&reader_frame_state);
            reset_builder(&tag_builder_state);
            reset_frame(&tag_frame_state);
            memset(&reader_levels_state, 0, sizeof(reader_levels_state));
            memset(&tag_ac_state, 0, sizeof(tag_ac_state));
            last_reader_us = UINT32_MAX;
            g_last_reader_label = "NONE";
        }
        last_sequence = sequence;
        processed_halves++;

        for(uint32_t offset = 0U; offset < STREAM_HALF_SAMPLES;
            offset += PROCESS_CHUNK_SAMPLES) {
            const uint16_t* block = processing_half + offset;
            uint64_t chunk_start = block_abs_start + offset;
            for(uint32_t i = 0; i < PROCESS_CHUNK_SAMPLES; i++) {
                uint16_t sample = block[i];
                if(sample < adc_min) adc_min = sample;
                if(sample > adc_max) adc_max = sample;
                if(sample <= 4U) adc_clip_low++;
                if(sample >= 4091U) adc_clip_high++;
            }
            append_raw_history(block, chunk_start, PROCESS_CHUNK_SAMPLES);
            process_half(
                block,
                chunk_start,
                &reader_levels_state,
                &tag_ac_state,
                &reader_builder_state,
                &reader_frame_state,
                &tag_builder_state,
                &tag_frame_state,
                log_file,
                &last_reader_us,
                &reader_frames,
                &tag_frames,
                &invalid_frames,
                &decode_stats_state);
            ui_reader_frames = reader_frames;
            collect_page_captures();
        }
    }

    uint32_t capture_elapsed_ms = furi_get_tick() - start_tick;
    furi_hal_rfid_adc_dma_stop();
    furi_hal_rfid_pins_reset();
    capture_active = false;

    finalize_segment(
        &reader_builder_state,
        &reader_frame_state,
        &tag_builder_state,
        &tag_frame_state,
        log_file,
        &last_reader_us,
        &reader_frames,
        &tag_frames,
        &invalid_frames,
        &decode_stats_state);
    uint32_t previous_reader_us = last_reader_us;
    const char* previous_reader_label = g_last_reader_label;
    if(log_reader_frame(
           log_file,
           &reader_frame_state,
           &last_reader_us,
           &reader_frames,
           &invalid_frames,
           &decode_stats_state)) {
        close_tag_window(
            &tag_builder_state,
            &tag_frame_state,
            log_file,
            previous_reader_us,
            previous_reader_label,
            &tag_frames,
            &invalid_frames,
            &decode_stats_state);
    }
    finalize_tag_segment(
        &tag_builder_state,
        &tag_frame_state,
        log_file,
        last_reader_us,
        g_last_reader_label,
        &tag_frames,
        &invalid_frames,
        &decode_stats_state);
    log_tag_frame(
        log_file,
        &tag_frame_state,
        last_reader_us,
        g_last_reader_label,
        &tag_frames,
        &invalid_frames,
        &decode_stats_state);

    dump_raw_diagnostic_capture(log_file);
    dump_edge_captures(log_file);
    snprintf(
        line,
        sizeof(line),
        "# page_consensus ready=%u decimal=%s em=00%08lX e0=%08lX n=%u e8=%08lX n=%u\n",
        capture_ready ? 1U : 0U,
        capture_ready ? captured_digits : "NONE",
        (unsigned long)captured_id,
        (unsigned long)best_direct_candidate(0)->word,
        best_direct_candidate(0)->count,
        (unsigned long)best_direct_candidate(1)->word,
        best_direct_candidate(1)->count);
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# done elapsed_ms=%lu reader_frames=%lu tag_frames=%lu invalid_frames=%lu\n",
        (unsigned long)capture_elapsed_ms,
        (unsigned long)reader_frames,
        (unsigned long)tag_frames,
        (unsigned long)invalid_frames);
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# adc_range min=%u max=%u p2p=%u clip_low=%lu clip_high=%lu\n",
        adc_min,
        adc_max,
        (unsigned int)(adc_max - adc_min),
        (unsigned long)adc_clip_low,
        (unsigned long)adc_clip_high);
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# stream completed=%lu processed=%lu dropped=%lu gaps=%lu pending_peak=%lu history_us=%u\n",
        (unsigned long)stream_completed_halves,
        (unsigned long)processed_halves,
        (unsigned long)stream_dropped_halves,
        (unsigned long)stream_gap_events,
        (unsigned long)stream_pending_peak,
        (unsigned int)((uint64_t)RAW_HISTORY_SAMPLES * 1000000U / SAMPLE_RATE_HZ));
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# diag reader_invalid=%lu reader_unrecognized=%lu reader_password_fuzzy_accepts=%lu reader_gate_resets=%lu tag_invalid=%lu tag_carrier_cuts=%lu tag_reader_low_skips=%lu tag_wait_reader_skips=%lu tag_window_timeouts=%lu tag_strong=%lu tag_weak=%lu tag_phase_locked=%lu tag_phase_prefix_restores=%lu tag_phase_rejects=%lu tag_diag_lines=%lu tag_header_run_promotions=%lu\n",
        (unsigned long)decode_stats_state.reader_invalid,
        (unsigned long)decode_stats_state.reader_unrecognized,
        (unsigned long)decode_stats_state.reader_password_fuzzy_accepts,
        (unsigned long)decode_stats_state.reader_gate_resets,
        (unsigned long)decode_stats_state.tag_invalid,
        (unsigned long)decode_stats_state.tag_carrier_cuts,
        (unsigned long)decode_stats_state.tag_reader_low_skips,
        (unsigned long)decode_stats_state.tag_wait_reader_skips,
        (unsigned long)decode_stats_state.tag_window_timeouts,
        (unsigned long)decode_stats_state.tag_strong,
        (unsigned long)decode_stats_state.tag_weak,
        (unsigned long)decode_stats_state.tag_phase_locked,
        (unsigned long)decode_stats_state.tag_phase_prefix_restores,
        (unsigned long)decode_stats_state.tag_phase_rejects,
        (unsigned long)decode_stats_state.tag_diag_lines,
        (unsigned long)decode_stats_state.tag_header_run_promotions);
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# reader_drop bad_order=%lu low_range=%lu total_range=%lu too_short=%lu adaptive_frames=%lu adaptive_attempts=%lu\n",
        (unsigned long)decode_stats_state.reader_drop_bad_order,
        (unsigned long)decode_stats_state.reader_drop_low_range,
        (unsigned long)decode_stats_state.reader_drop_total_range,
        (unsigned long)decode_stats_state.reader_drop_too_short,
        (unsigned long)decode_stats_state.reader_adaptive_frames,
        (unsigned long)decode_stats_state.reader_adaptive_attempts);
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# reader_pair low_min=%lu low_max=%lu total_min=%lu total_max=%lu\n",
        (unsigned long)decode_stats_state.reader_pair_low_min,
        (unsigned long)decode_stats_state.reader_pair_low_max,
        (unsigned long)decode_stats_state.reader_pair_total_min,
        (unsigned long)decode_stats_state.reader_pair_total_max);
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# tag_drop no_nrz=%lu no_manchester=%lu no_header=%lu payload_short=%lu all_same=%lu adaptive_frames=%lu adaptive_attempts=%lu\n",
        (unsigned long)decode_stats_state.tag_drop_no_nrz,
        (unsigned long)decode_stats_state.tag_drop_no_manchester,
        (unsigned long)decode_stats_state.tag_drop_no_header,
        (unsigned long)decode_stats_state.tag_drop_payload_short,
        (unsigned long)decode_stats_state.tag_drop_all_same,
        (unsigned long)decode_stats_state.tag_adaptive_frames,
        (unsigned long)decode_stats_state.tag_adaptive_attempts);
    write_line(log_file, line);

    snprintf(
        line,
        sizeof(line),
        "# tag_seg sym1=%lu sym2=%lu sym3=%lu long=%lu\n",
        (unsigned long)decode_stats_state.tag_seg_1t,
        (unsigned long)decode_stats_state.tag_seg_2t,
        (unsigned long)decode_stats_state.tag_seg_3t,
        (unsigned long)decode_stats_state.tag_seg_long);
    write_line(log_file, line);

    // V11 note: tag windows are now also explicitly closed on each successfully decoded reader frame
    // (previous reply ends when new command is observed). This is more protocol-aware than per-block raw dips.

    flush_log(log_file);
    storage_file_close(log_file);
    storage_file_free(log_file);
    furi_record_close(RECORD_STORAGE);

    gui_remove_view_port(gui, view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(view_port);
    furi_message_queue_free(ui.input_queue);

    if(capture_ready) {
        storage = furi_record_open(RECORD_STORAGE);
        bool saved = offer_save_credential(storage);
        furi_record_close(RECORD_STORAGE);
        FURI_LOG_I(TAG, "Credential save: %s", saved ? "ok" : "not saved");
    }

    FURI_LOG_I(TAG, "Saved log: %s", log_path);
    FURI_LOG_I(
        TAG,
        "Done: R=%lu T=%lu invalid=%lu",
        (unsigned long)reader_frames,
        (unsigned long)tag_frames,
        (unsigned long)invalid_frames);

    return 0;
}
