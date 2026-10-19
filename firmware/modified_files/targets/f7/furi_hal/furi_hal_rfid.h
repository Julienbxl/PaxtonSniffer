/**
 * @file furi_hal_rfid.h
 * RFID HAL API
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize RFID subsystem
 */
void furi_hal_rfid_init(void);

/** Config rfid pins to reset state
 */
void furi_hal_rfid_pins_reset(void);

/** Release rfid pull pin
 */
void furi_hal_rfid_pin_pull_release(void);

/** Pulldown rfid pull pin
 */
void furi_hal_rfid_pin_pull_pulldown(void);

/** Start read timer
 * @param      freq        timer frequency
 * @param      duty_cycle  timer duty cycle, 0.0-1.0
 */
void furi_hal_rfid_tim_read_start(float freq, float duty_cycle);

/** Pause read timer, to be able to continue later
 */
void furi_hal_rfid_tim_read_pause(void);

/** Continue read timer
 */
void furi_hal_rfid_tim_read_continue(void);

/** Stop read timer
 */
void furi_hal_rfid_tim_read_stop(void);

typedef void (*FuriHalRfidReadCaptureCallback)(bool level, uint32_t duration, void* context);

void furi_hal_rfid_tim_read_capture_start(FuriHalRfidReadCaptureCallback callback, void* context);

void furi_hal_rfid_tim_read_capture_stop(void);

typedef void (*FuriHalRfidDMACallback)(bool half, void* context);

void furi_hal_rfid_tim_emulate_dma_start(
    uint32_t* duration,
    uint32_t* pulse,
    size_t length,
    FuriHalRfidDMACallback callback,
    void* context);

void furi_hal_rfid_tim_emulate_dma_stop(void);

/** Set read timer period
 *
 * @param      period  overall duration
 */
void furi_hal_rfid_set_read_period(uint32_t period);

/** Set read timer pulse
 *
 * @param      pulse  duration of high level
 */
void furi_hal_rfid_set_read_pulse(uint32_t pulse);

/** Start/Enable comparator */
void furi_hal_rfid_comp_start(void);

/** Stop/Disable comparator */
void furi_hal_rfid_comp_stop(void);

typedef void (*FuriHalRfidCompCallback)(bool level, void* context);

/** Set comparator callback */
void furi_hal_rfid_comp_set_callback(FuriHalRfidCompCallback callback, void* context);

/** Start/Enable Field Presence detect */
void furi_hal_rfid_field_detect_start(void);

/** Stop/Disable Field Presence detect */
void furi_hal_rfid_field_detect_stop(void);

/** Check Field Presence
 *
 * @param[out] frequency  pointer to frequency value to be set if filed detected
 *
 * @return     true if field is present, false if not
 */
bool furi_hal_rfid_field_is_present(uint32_t* frequency);

/** Start continuous ADC DMA capture triggered by TIM2
 *
 * The DMA runs in circular mode. Callback is called at half-buffer and
 * full-buffer boundaries with the same boolean convention as RFID DMA
 * callbacks: true for first half, false for second half.
 *
 * This is a passive receive path. RFID_PULL is held high to preserve the
 * short reader field gaps observed with the V17 topology, while RFID_OUT is
 * driven low. RFID_CARRIER remains analog because TIM2 is used as ADC trigger.
 *
 * @param buffer       Destination buffer for 12-bit ADC samples
 * @param samples      Number of samples in the circular buffer, must be even
 * @param sample_rate  Sampling rate in Hz (e.g. 500000 or 1000000)
 * @param callback     Half/full buffer callback
 * @param context      User context passed to callback
 */
void furi_hal_rfid_adc_dma_stream_start(
    uint16_t* buffer,
    size_t samples,
    uint32_t sample_rate,
    FuriHalRfidDMACallback callback,
    void* context);

/** Stop ADC DMA capture
 */
void furi_hal_rfid_adc_dma_stop(void);

/** Start a bounded ADC DMA capture without changing TIM1 or the RF output pins.
 * The caller owns the active carrier and must stop it separately.
 */
void furi_hal_rfid_adc_dma_start(uint16_t* buffer, size_t samples, uint32_t sample_rate);

/** Wait for a bounded capture to complete. Does not stop the RF carrier.
 * Call from thread context with interrupts enabled, then call adc_dma_stop().
 */
bool furi_hal_rfid_adc_dma_wait_done(uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
