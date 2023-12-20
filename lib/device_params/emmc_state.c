// SPDX-License-Identifier: GPL-2.0+

#include <blk.h>
#include <common.h>
#include <part.h>
#include <device_params.h>

// Forward-declarations of static functions
static int get_emmc_state_internal(uint32_t state_addr, struct emmc_state *emmc_state);
static int write_emmc_state_internal(uint32_t state_addr, const struct emmc_state *emmc_state);

static int get_emmc_state_internal(uint32_t state_addr, struct emmc_state *emmc_state)
{
	struct blk_desc *mmc = mmc_get_device_params_dev();
	if (!mmc)
	{
		return 1;
	}

	uint8_t buf[CONFIG_DEVICE_PARAMS_EMMC_BLOCKSIZE];
	if (mmc->blksz > sizeof(buf))
	{
		printf("MMC blocksize too big: %u\n", mmc->blksz);
		return 1;
	}

	if (state_addr % mmc->blksz != 0)
	{
		printf("EMMC state addr %u not aligned to MMC blocksize\n", state_addr);
		return 1;
	}

	lbaint_t blk = state_addr / mmc->blksz;
	if (blk_dread(mmc, blk, 1, buf) != 1)
	{
		printf("Failed to read EMMC state block %u\n", blk);
		return 1;
	}

	memcpy(emmc_state, buf, sizeof(*emmc_state));

	return 0;
}

static int write_emmc_state_internal(uint32_t state_addr, const struct emmc_state *emmc_state)
{
	struct blk_desc *mmc = mmc_get_device_params_dev();
	if (!mmc)
	{
		return 1;
	}

	uint8_t buf[CONFIG_DEVICE_PARAMS_EMMC_BLOCKSIZE];
	if (mmc->blksz > sizeof(buf))
	{
		printf("MMC blocksize too big: %u\n", mmc->blksz);
		return 1;
	}

	if (state_addr % mmc->blksz != 0)
	{
		printf("EMMC state addr %u not aligned to MMC blocksize\n", state_addr);
		return 1;
	}

	memcpy(buf, emmc_state, sizeof(*emmc_state));

	lbaint_t blk = state_addr / mmc->blksz;
	if (blk_dwrite(mmc, blk, 1, buf) != 1)
	{
		printf("Failed to write EMMC state block %u\n", blk);
		return 1;
	}

	return 0;
}

int get_emmc_state(struct emmc_state *emmc_state)
{
	return get_emmc_state_internal(device_flash_params.emmc_layout.state_addr, emmc_state);
}

int write_emmc_state(const struct emmc_state *emmc_state)
{
	return write_emmc_state_internal(device_flash_params.emmc_layout.state_addr, emmc_state);
}

