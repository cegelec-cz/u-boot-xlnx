// SPDX-License-Identifier: GPL-2.0+
#ifndef DEVICE_PARAMS_EMMC_LAYOUT_H
#define DEVICE_PARAMS_EMMC_LAYOUT_H

#include <device_params.h>
#include <linux/types.h>

void write_default_emmc_layout(struct emmc_layout *emmc_layout);
uint32_t compute_emmc_layout_crc(const struct emmc_layout *emmc_layout);
int check_emmc_layout(const struct emmc_layout *emmc_layout, const char **feedback);

#endif // DEVICE_PARAMS_EMMC_LAYOUT_H
