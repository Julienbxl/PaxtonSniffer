// SPDX-License-Identifier: GPL-3.0-only
#include <furi.h>

int32_t hitag2_protocol_run(void* context);

int32_t paxton_sniffer_app(void* context) {
    return hitag2_protocol_run(context);
}
