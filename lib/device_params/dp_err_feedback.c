// SPDX-License-Identifier: GPL-2.0+
#include "dp_err_feedback.h"

#include <common.h>

static const char *const dp_err_feedback[DEVPARAMS_ERR_COUNT] = {
	[DEVPARAMS_ERR_NONE] = "",
	[DEVPARAMS_ERR_ETH_SETTINGS_BAD_CRC] = "ethernet settings: CRC check failed",
	[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_MAC] = "ethernet settings: invalid MAC address",
	[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_IPADDR] = "ethernet settings: invalid IP address",
	[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_NETMASK] = "ethernet settings: invalid netmask",
	[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_GATEWAY] = "ethernet settings: invalid gateway IP address",
	[DEVPARAMS_ERR_EMMC_LAYOUT_BAD_CRC] = "emmc layout: CRC check failed",
	[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_STATE_SIZE] = "emmc layout: invalid state partition size",
	[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_BACKUP_SIZE] = "emmc layout: invalid backup partition size",
	[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_SW_SIZE] = "emmc layout: invalid software partition size",
	[DEVPARAMS_ERR_EMMC_LAYOUT_OVERLAP] = "emmc layout: partitions overlap emmc_state or each other",
	[DEVPARAMS_ERR_EMMC_LAYOUT_ALIGNMENT] = "emmc layout: starting addresses or partition sizes are not aligned to eMMC blocksize",
	[DEVPARAMS_ERR_INTERNAL] = "internal error occured when validating device parameters",
};

const char *get_dp_err_feedback(device_params_err_t err)
{
	if (err >= DEVPARAMS_ERR_COUNT)
		return NULL;

	return dp_err_feedback[err];
}