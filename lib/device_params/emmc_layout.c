// SPDX-License-Identifier: GPL-2.0+
#include "emmc_layout.h"

#include "dp_err_feedback.h"

#include <cassert.h>
#include <device_params.h>

// Check overlap of state <-> backup, state <-> software and backup <-> software partitions
#define CHECK_EMMC_OVERLAP(state_start, state_size,                \
						   backup_start, backup_size,              \
						   software_start, software_size)          \
	(                                                              \
		((state_start) >= ((backup_start) + (backup_size)) ||      \
		 (backup_start) >= ((state_start) + (state_size))) &&      \
		((state_start) >= ((software_start) + (software_size)) ||  \
		 (software_start) >= ((state_start) + (state_size))) &&    \
		((backup_start) >= ((software_start) + (software_size)) || \
		 (software_start) >= ((backup_start) + (backup_size))))

// Check alignment of state, backup and software partitions
#define CHECK_EMMC_ALIGNMENT(blocksize, state_start, state_size,                     \
							 backup_start, backup_size,                              \
							 software_start, software_size)                          \
	(                                                                                \
		((state_start) % (blocksize) == 0) && ((state_size) % (blocksize) == 0) &&   \
		((backup_start) % (blocksize) == 0) && ((backup_size) % (blocksize) == 0) && \
		((software_start) % (blocksize) == 0) && ((software_size) % (blocksize) == 0))

static const struct emmc_layout default_emmc_layout = {
	.state_addr = CONFIG_DEFAULT_EMMC_STATE_ADDR,
	.state_size = CONFIG_DEVICE_PARAMS_EMMC_BLOCKSIZE,
	.recovery_addr = CONFIG_DEFAULT_EMMC_BACKUP_ADDR,
	.recovery_size = CONFIG_DEFAULT_EMMC_BACKUP_SIZE,
	.software_addr = CONFIG_DEFAULT_EMMC_SOFTWARE_ADDR,
	.software_size = CONFIG_DEFAULT_EMMC_SOFTWARE_SIZE,
	.crc = 0,
};

// Compile-time check of default emmc layout validity
CASSERT(
	CONFIG_DEVICE_PARAMS_EMMC_BLOCKSIZE >= sizeof(struct emmc_state) &&
	CONFIG_DEFAULT_EMMC_BACKUP_SIZE >= CONFIG_MAX_SW_BLOB_SIZE &&
	CONFIG_DEFAULT_EMMC_SOFTWARE_SIZE >= CONFIG_MAX_SW_BLOB_SIZE &&
	CHECK_EMMC_OVERLAP(CONFIG_DEFAULT_EMMC_STATE_ADDR,
					   CONFIG_DEVICE_PARAMS_EMMC_BLOCKSIZE,
					   CONFIG_DEFAULT_EMMC_BACKUP_ADDR,
					   CONFIG_DEFAULT_EMMC_BACKUP_SIZE,
					   CONFIG_DEFAULT_EMMC_SOFTWARE_ADDR,
					   CONFIG_DEFAULT_EMMC_SOFTWARE_SIZE) &&
	CHECK_EMMC_ALIGNMENT(CONFIG_DEVICE_PARAMS_EMMC_BLOCKSIZE,
						 CONFIG_DEFAULT_EMMC_STATE_ADDR,
						 CONFIG_DEVICE_PARAMS_EMMC_BLOCKSIZE,
						 CONFIG_DEFAULT_EMMC_BACKUP_ADDR,
						 CONFIG_DEFAULT_EMMC_BACKUP_SIZE,
						 CONFIG_DEFAULT_EMMC_SOFTWARE_ADDR,
						 CONFIG_DEFAULT_EMMC_SOFTWARE_SIZE));

void write_default_emmc_layout(struct emmc_layout *emmc_layout)
{
	*emmc_layout = default_emmc_layout;
	emmc_layout->crc = compute_emmc_layout_crc(emmc_layout);
}

uint32_t compute_emmc_layout_crc(const struct emmc_layout *emmc_layout)
{
	return crc32(0, (const uint8_t *)emmc_layout,
				 sizeof(*emmc_layout) - sizeof(emmc_layout->crc));
}

int check_emmc_layout(const struct emmc_layout *emmc_layout, const char **feedback)
{
	int ret = 0;
	const char *feedback_str = NULL;

	struct blk_desc *mmc = mmc_get_device_params_dev();
	if (!mmc)
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_INTERNAL);
		ret = 1;
	}
	else if (emmc_layout->crc != compute_emmc_layout_crc(emmc_layout))
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_EMMC_LAYOUT_BAD_CRC);
		ret = 1;
	}
	else if (emmc_layout->state_size != mmc->blksz)
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_STATE_SIZE);
		ret = 1;
	}
	else if (emmc_layout->recovery_size < CONFIG_MAX_SW_BLOB_SIZE)
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_BACKUP_SIZE);
		ret = 1;
	}
	else if (emmc_layout->software_size < CONFIG_MAX_SW_BLOB_SIZE)
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_SW_SIZE);
		ret = 1;
	}
	else if (!CHECK_EMMC_OVERLAP(
				 emmc_layout->state_addr,
				 emmc_layout->state_size,
				 emmc_layout->recovery_addr,
				 emmc_layout->recovery_size,
				 emmc_layout->software_addr,
				 emmc_layout->software_size))
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_EMMC_LAYOUT_OVERLAP);
		ret = 1;
	}
	else if (!CHECK_EMMC_ALIGNMENT(
				 mmc->blksz,
				 emmc_layout->state_addr,
				 emmc_layout->state_size,
				 emmc_layout->recovery_addr,
				 emmc_layout->recovery_size,
				 emmc_layout->software_addr,
				 emmc_layout->software_size))
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_EMMC_LAYOUT_ALIGNMENT);
		ret = 1;
	}

	if (feedback_str)
	{
		printf("%s\n", feedback_str);
		if (feedback)
			*feedback = feedback_str;
	}

	return ret;
}