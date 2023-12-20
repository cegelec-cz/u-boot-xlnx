// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2014 Broadcom Corporation.
 */

#include <config.h>
#include <common.h>
#include <device_params.h>
#include <blk.h>
#include <env.h>
#include <fastboot.h>
#include <fastboot-internal.h>
#include <fb_mmc.h>
#include <image-sparse.h>
#include <image.h>
#include <log.h>
#include <part.h>
#include <mmc.h>
#include <div64.h>
#include <linux/compat.h>
#include <android_image.h>
#include <firmware_blob.h>
#include <boot_policy.h>
#include <validate_blob.h>

// FIXME
#define CONFIG_FASTBOOT_FLASH_MMC_DEV 0

#define FASTBOOT_MAX_BLK_WRITE 16384

/**
 * fb_mmc_blk_write() - Write/erase MMC in chunks of FASTBOOT_MAX_BLK_WRITE
 *
 * @block_dev: Pointer to block device
 * @start: First block to write/erase
 * @blkcnt: Count of blocks
 * @buffer: Pointer to data buffer for write or NULL for erase
 */
static lbaint_t fb_mmc_blk_write(struct blk_desc *block_dev, lbaint_t start,
								 lbaint_t blkcnt, const void *buffer)
{
	lbaint_t blk = start;
	lbaint_t blks_written;
	lbaint_t cur_blkcnt;
	lbaint_t blks = 0;
	int i;

	for (i = 0; i < blkcnt; i += FASTBOOT_MAX_BLK_WRITE)
	{
		cur_blkcnt = min((int)blkcnt - i, FASTBOOT_MAX_BLK_WRITE);
		if (buffer)
		{
			if (fastboot_progress_callback)
				fastboot_progress_callback("writing");
			blks_written = blk_dwrite(block_dev, blk, cur_blkcnt,
									  buffer + (i * block_dev->blksz));
		}
		else
		{
			if (fastboot_progress_callback)
				fastboot_progress_callback("erasing");
			blks_written = blk_derase(block_dev, blk, cur_blkcnt);
		}
		blk += blks_written;
		blks += blks_written;
	}
	return blks;
}

static void write_raw_image(struct blk_desc *dev_desc,
							struct disk_partition *info, const char *part_name,
							void *buffer, u32 download_bytes, char *response)
{
	lbaint_t blkcnt;
	lbaint_t blks;

	/* determine number of blocks to write */
	blkcnt = ((download_bytes + (info->blksz - 1)) & ~(info->blksz - 1));
	blkcnt = lldiv(blkcnt, info->blksz);

	if (blkcnt > info->size)
	{
		pr_err("too large for partition: '%s'\n", part_name);
		fastboot_fail("too large for partition", response);
		return;
	}

	puts("Flashing Raw Image\n");

	blks = fb_mmc_blk_write(dev_desc, info->start, blkcnt, buffer);

	if (blks != blkcnt)
	{
		pr_err("failed writing to device %d\n", dev_desc->devnum);
		fastboot_fail("failed writing to device", response);
		return;
	}

	printf("........ wrote " LBAFU " bytes to '%s'\n", blkcnt * info->blksz,
		   part_name);
	fastboot_okay(NULL, response);
}

struct blk_desc *fastboot_mmc_get_dev(char *response)
{
	struct blk_desc *ret = blk_get_dev("mmc",
									   CONFIG_DEVICE_PARAMS_MMC_DEV);

	if (!ret || ret->type == DEV_TYPE_UNKNOWN)
	{
		pr_err("invalid mmc device\n");
		fastboot_fail("invalid mmc device", response);
		return NULL;
	}
	return ret;
}

/**
 * fastboot_mmc_flash_write() - Write image to eMMC for fastboot
 *
 * @cmd: Named partition to write image to
 * @download_buffer: Pointer to image data
 * @download_bytes: Size of image data
 * @response: Pointer to fastboot response buffer
 */
void fastboot_mmc_flash_write(const char *cmd, void *download_buffer,
							  u32 download_bytes, char *response)
{
	if (!cmd)
	{
		fastboot_fail("Partition name (software/recovery) not specified", response);
		return;
	}

	int is_recovery_flash = 0;
	if (strcmp(cmd, "recovery") == 0)
	{
		is_recovery_flash = 1;
	}
	else if (strcmp(cmd, "software") != 0)
	{
		fastboot_fail("Invalid partition name (expecting software/recovery)", response);
		return;
	}

	struct validate_blob_input validate_blob_input = {
		.blob = download_buffer,
		.blob_len = download_bytes,
		.board_boot_policy = device_flash_params.board_boot_policy,
		.board_project_id = device_flash_params.project_id,
		.board_partition = is_recovery_flash ? BOARD_PARTITION_RECOVERY : BOARD_PARTITION_SOFTWARE,
	};

	const char *feedback = NULL;
	if (validate_blob(&validate_blob_input, &feedback) != 0)
	{
		const char *fail_msg = "Validation of firmware blob failed";
		if (feedback)
			fastboot_response("FAIL", response, "%s: %s", fail_msg, feedback);
		else
			fastboot_fail(fail_msg, response);

		return;
	}

	uint32_t mmc_dest_addr;
	uint32_t mmc_partition_size;
	if (is_recovery_flash)
	{
		mmc_dest_addr = device_flash_params.emmc_layout.recovery_addr;
		mmc_partition_size = device_flash_params.emmc_layout.recovery_size;
	}
	else
	{
		struct emmc_state emmc_state = {.sw_state = SW_STATE_UPDATED};
		if (write_emmc_state(&emmc_state) != 0)
		{
			fastboot_fail("write_emmc_state() failed", response);
			return;
		}

		mmc_dest_addr = device_flash_params.emmc_layout.software_addr;
		mmc_partition_size = device_flash_params.emmc_layout.software_size;
	}

	struct blk_desc *dev_desc = fastboot_mmc_get_dev(response);
	if (!dev_desc)
		return;

	struct disk_partition partition_info = {
		.start = mmc_dest_addr / dev_desc->blksz,
		.size = mmc_partition_size / dev_desc->blksz,
		.blksz = dev_desc->blksz,
	};

	write_raw_image(dev_desc, &partition_info, cmd, download_buffer, download_bytes, response);
}

/**
 * fastboot_mmc_flash_erase() - Erase eMMC for fastboot
 *
 * @cmd: Named partition to erase
 * @response: Pointer to fastboot response buffer
 */
void fastboot_mmc_erase(const char *cmd, char *response)
{
	if (!cmd)
	{
		fastboot_fail("Partition name (software/recovery) not specified", response);
		return;
	}

	uint32_t mmc_dest_addr;
	uint32_t mmc_partition_size;

	if (strcmp(cmd, "recovery") == 0)
	{
		mmc_dest_addr = device_flash_params.emmc_layout.recovery_addr;
		mmc_partition_size = device_flash_params.emmc_layout.recovery_size;
	}
	else if (strcmp(cmd, "software") == 0)
	{
		mmc_dest_addr = device_flash_params.emmc_layout.software_addr;
		mmc_partition_size = device_flash_params.emmc_layout.software_size;

		struct emmc_state emmc_state = {.sw_state = SW_STATE_EMPTY};
		if (write_emmc_state(&emmc_state) != 0)
		{
			fastboot_fail("write_emmc_state() failed", response);
			return;
		}
	}
	else
	{
		fastboot_fail("Invalid partition name (expecting software/recovery)", response);
		return;
	}

	struct mmc *mmc = find_mmc_device(CONFIG_DEVICE_PARAMS_MMC_DEV);
	if (!mmc)
	{
		fastboot_fail("find_mmc_device() call failed", response);
		return;
	}

	struct blk_desc *dev_desc = fastboot_mmc_get_dev(response);
	if (!dev_desc)
		return;

	/* Align blocks to erase group size to avoid erasing other partitions */
	lbaint_t start = mmc_dest_addr / dev_desc->blksz;
	lbaint_t count = mmc_partition_size / dev_desc->blksz;
	lbaint_t grp_size = mmc->erase_grp_size;
	lbaint_t blks_start = (start + grp_size - 1) & ~(grp_size - 1);
	lbaint_t blks_size = 0;
	if (count >= grp_size)
		blks_size = (count - (blks_start - start)) &
					(~(grp_size - 1));

	printf("Erasing blocks " LBAFU " to " LBAFU " due to alignment\n",
		   blks_start, blks_start + blks_size);

	lbaint_t blks = fb_mmc_blk_write(dev_desc, blks_start, blks_size, NULL);

	if (blks != blks_size)
	{
		pr_err("failed erasing from device %d\n", dev_desc->devnum);
		fastboot_fail("failed erasing from device", response);
		return;
	}

	printf("........ erased " LBAFU " bytes from '%s'\n",
		   blks_size * dev_desc->blksz, cmd);
	fastboot_okay(NULL, response);
}
