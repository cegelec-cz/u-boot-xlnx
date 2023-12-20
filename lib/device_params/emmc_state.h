// SPDX-License-Identifier: GPL-2.0+
#ifndef DEVICE_PARAMS_EMMC_STATE_H
#define DEVICE_PARAMS_EMMC_STATE_H

#include <device_params.h>
#include <linux/types.h>

int get_emmc_state(struct emmc_state *emmc_state);
int write_emmc_state(const struct emmc_state *emmc_state);

#endif // DEVICE_PARAMS_EMMC_STATE_H
