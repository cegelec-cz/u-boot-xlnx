// SPDX-License-Identifier: GPL-2.0+
/*
 * Command for executing Cegelec boot logic
 *
 * Copyright (c) 2023 - Cegelec a.s.
 */

#include <blk.h>
#include <cassert.h>
#include <common.h>
#include <command.h>
#include <device_params.h>
#include <div64.h>
#include <env.h>
#include <firmware_blob.h>
#include <validate_blob.h>

typedef enum
{
	CRITICAL_BOOT_FAILURE_GET_MMC_STATE,
	CRITICAL_BOOT_FAILURE_WRITE_MMC_STATE,
	CRITICAL_BOOT_FAILURE_FPGA_LOAD_FAIL,
	CRITICAL_BOOT_FAILURE_BOOTELF_FAIL,
	CRITICAL_BOOT_FAILURE_BOOTELF_NOT_EXECUTED,
	CRITICAL_BOOT_FAILURE_COUNT,
} critical_boot_failure_t;

const char *const critical_boot_failure_msg[CRITICAL_BOOT_FAILURE_COUNT] = {
	[CRITICAL_BOOT_FAILURE_GET_MMC_STATE] = "failed to retrieve EMMC state",
	[CRITICAL_BOOT_FAILURE_WRITE_MMC_STATE] = "failed to write EMMC state",
	[CRITICAL_BOOT_FAILURE_FPGA_LOAD_FAIL] = "failed to load FPGA bitstream",
	[CRITICAL_BOOT_FAILURE_BOOTELF_FAIL] = "failed to boot ELF application",
	[CRITICAL_BOOT_FAILURE_BOOTELF_NOT_EXECUTED] = "bootelf command not executed",
};

static int
load_emmc_image(uint32_t addr)
{
	struct blk_desc *dev = mmc_get_device_params_dev();
	if (!dev)
	{
		printf("Failed to get MMC device\n");
		return 1;
	}

	if (addr % dev->blksz != 0)
	{
		printf("Source addr not aligned to MMC block size\n");
		return 1;
	}

	void *buf = (void *)CONFIG_FASTBOOT_BUF_ADDR;
	uint32_t buf_size = CONFIG_FASTBOOT_BUF_SIZE;

	if (buf_size < dev->blksz)
	{
		printf("Invalid load buffer size");
		return 1;
	}

	// Read first block
	lbaint_t blk = addr / dev->blksz;
	if (blk_dread(dev, blk, 1, buf) != 1)
	{
		printf("Failed to read initial block from EMMC\n");
		return 1;
	}

	// Get total blob size
	struct blob_header *blob_header = (struct blob_header *)buf;

	uint32_t blob_size = blob_header->blob_size;
	if (blob_size > CONFIG_FASTBOOT_BUF_SIZE)
	{
		printf("Invalid load buffer size\n");
		return 1;
	}

	// Read in rest of blob
	lbaint_t blkcnt = ((blob_size + (dev->blksz - 1)) & ~(dev->blksz - 1));
	blkcnt = lldiv(blkcnt, dev->blksz);

	if (blkcnt * dev->blksz > CONFIG_FASTBOOT_BUF_SIZE)
	{
		printf("Invalid load buffer size\n");
		return 1;
	}

	if (blkcnt == 0)
	{
		printf("Invalid blob size\n");
		return 1;
	}

	--blkcnt;
	++blk;

	if (blk_dread(dev, blk, blkcnt, buf + dev->blksz) != blkcnt)
	{
		printf("Failed to load image from EMMC\n");
		return 1;
	}

	return 0;
}

static void start_fastboot()
{
	initialize_fb_env_from_loaded_params();
	while (1) // Attempt to run fastboot indefinitely
		run_command("fastboot udp", 0);
}

static void critical_boot_failure(critical_boot_failure_t failure)
{
	const char *msg = critical_boot_failure_msg[failure];
	if (!msg)
		msg = "critical boot failure occured";

	env_set("fastboot.critical_bootfail", msg);

	start_fastboot();
}

static void boot_loaded_image()
{
	const struct blob_header *blob_header = (struct blob_header *)CONFIG_FASTBOOT_BUF_ADDR;
	uint32_t bitstream_load_addr = (uint32_t)blob_header + sizeof(*blob_header) + blob_header->package_identifier_len;
	uint32_t elf_load_addr = bitstream_load_addr + blob_header->bitstream_len;

	if (run_commandf("fpga loadb 0 %x %x", bitstream_load_addr, blob_header->bitstream_len) != 0)
	{
		critical_boot_failure(CRITICAL_BOOT_FAILURE_FPGA_LOAD_FAIL);
		return;
	}

	env_set("autostart", "1");
	if (run_commandf("bootelf %x", elf_load_addr) != 0)
	{
		critical_boot_failure(CRITICAL_BOOT_FAILURE_BOOTELF_FAIL);
		return;
	}

	// should never get here
	critical_boot_failure(CRITICAL_BOOT_FAILURE_BOOTELF_NOT_EXECUTED);
}

static void init_validate_blob_input(struct validate_blob_input *validate_blob_input, board_partition_t partition)
{
	const struct blob_header *blob_header = (const struct blob_header *)CONFIG_FASTBOOT_BUF_ADDR;

	validate_blob_input->blob = blob_header;
	validate_blob_input->blob_len = blob_header->blob_size;
	validate_blob_input->board_boot_policy = device_flash_params.board_boot_policy;
	validate_blob_input->board_project_id = device_flash_params.project_id;
	validate_blob_input->board_partition = partition;
}

static void attempt_recovery_boot()
{
	env_set("fastboot.bootstep_recovery", "attempting recovery boot");

	if (load_emmc_image(device_flash_params.emmc_layout.recovery_addr) != 0)
	{
		env_set("fastboot.bootstep_recovery", "loading of recovery image from eMMC failed");
		start_fastboot();
		return;
	}

	struct validate_blob_input validate_blob_input;
	init_validate_blob_input(&validate_blob_input, BOARD_PARTITION_RECOVERY);

	const char *feedback = NULL;
	if (validate_blob(&validate_blob_input, &feedback) != 0)
	{
		feedback = (feedback != NULL) ? feedback : "validation of image blob failed";
		env_set("fastboot.bootstep_recovery", feedback);
		start_fastboot();
		return;
	}

	boot_loaded_image();
}

static void attempt_primary_sw_boot()
{
	env_set("fastboot.bootstep_primary_sw", "attempting primary sw boot");

	if (load_emmc_image(device_flash_params.emmc_layout.software_addr) != 0)
	{
		env_set("fastboot.bootstep_primary_sw", "loading of primary image from eMMC failed");
		attempt_recovery_boot();
		return;
	}

	struct validate_blob_input validate_blob_input;
	init_validate_blob_input(&validate_blob_input, BOARD_PARTITION_SOFTWARE);

	const char *feedback = NULL;
	if (validate_blob(&validate_blob_input, &feedback) != 0)
	{
		feedback = (feedback != NULL) ? feedback : "validation of image blob failed";
		env_set("fastboot.bootstep_primary_sw", feedback);
		attempt_recovery_boot();
		return;
	}

	boot_loaded_image();
}

static void write_state_and_boot(void (*boot_cb)(void), const struct emmc_state *emmc_state)
{
	if (write_emmc_state(emmc_state) == 0)
		return boot_cb();
	else
		return critical_boot_failure(CRITICAL_BOOT_FAILURE_WRITE_MMC_STATE);
}

static void initialize_diagnostic_env_variables()
{
	const char *na = "not attempted";
	env_set("fastboot.bootstep_primary_sw", na);
	env_set("fastboot.bootstep_recovery", na);
	env_set("fastboot.critical_bootfail", "critical boot failure not present");
}

int do_cegboot(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	initialize_diagnostic_env_variables();

	struct emmc_state emmc_state;
	if (get_emmc_state(&emmc_state) != 0)
		critical_boot_failure(CRITICAL_BOOT_FAILURE_GET_MMC_STATE);

	if (emmc_state.sw_state > SW_STATE_COUNT)
	{
		emmc_state.sw_state = SW_STATE_FAILED;
		if (write_emmc_state(&emmc_state) != 0)
			critical_boot_failure(CRITICAL_BOOT_FAILURE_WRITE_MMC_STATE);
	}

	switch (emmc_state.sw_state)
	{
	case SW_STATE_UPDATED:
		emmc_state.sw_state = SW_STATE_STARTED;
		write_state_and_boot(attempt_primary_sw_boot, &emmc_state);
		break;
	case SW_STATE_VALID:
		attempt_primary_sw_boot();
		break;
	case SW_STATE_FASTBOOT:
		emmc_state.sw_state = (emmc_state.sw_state == SW_STATE_VALID) ? SW_STATE_UPDATED : emmc_state.sw_state;
		write_state_and_boot(start_fastboot, &emmc_state);
		break;
	case SW_STATE_STARTED:
		emmc_state.sw_state = SW_STATE_FAILED;
		write_state_and_boot(attempt_recovery_boot, &emmc_state);
		break;
	case SW_STATE_EMPTY:
	case SW_STATE_FAILED:
	default:
		attempt_recovery_boot();
		break;
	}

	// Should not get here
	return 1;
}

U_BOOT_CMD(
	cegboot, 1, 0, do_cegboot,
	"Execute Cegelec boot logic\n",
	"Attempt to boot primary/recovery SW from eMMC based on device state "
	"and start fastboot server if no bootable software exists on eMMC\n");
