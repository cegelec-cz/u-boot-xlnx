// SPDX-License-Identifier: GPL-2.0+
#include "flash_params.h"

#include "emmc_layout.h"
#include "ethernet_settings.h"
#include "fb_env_vars.h"

#include <blk.h>
#include <cassert.h>
#include <common.h>
#include <net.h>
#include <part.h>
#include <spi_flash.h>
#include <device_params.h>
#include <boot_policy.h>

// TODO: remove
#define MAC_IP_ADDR_STR_LEN 20

#define MIN_OFFSET_FROM_START 5242880UL		   // 5 MiB
#define FLASH_PARAMS_OFFSET_FROM_END 1048576UL // 1 MiB

// Compile-time check that flash_params fit into last 1MiB
CASSERT(sizeof(struct flash_params) < FLASH_PARAMS_OFFSET_FROM_END);

// Forward-declarations of static functions
static int get_flash_params_offset(const struct spi_nor *flash);
static struct spi_nor *probe_flash(void);
static int write_params_to_flash(struct spi_nor *flash, uint32_t flash_params_offset,
								 const struct flash_params *flash_params);
static int validate_flash_params(struct flash_params *flash_params, int validate_modified);
static int init_device_flash_params(void);

struct flash_params device_flash_params;
struct flash_params modified_device_flash_params;

static int get_flash_params_offset(const struct spi_nor *flash)
{
	return flash->size - FLASH_PARAMS_OFFSET_FROM_END;
}

static struct spi_nor *probe_flash(void)
{
	struct spi_nor *flash = spi_flash_probe(CONFIG_SF_DEFAULT_BUS,
											CONFIG_SF_DEFAULT_CS,
											CONFIG_SF_DEFAULT_SPEED,
											CONFIG_SF_DEFAULT_MODE);
	if (!flash)
	{
		printf("Failed to probe SPI flash\n");
		return NULL;
	}

	// Flash params start in last 1MiB of flash and must not be placed in first
	// 5 MiB of flash to prevent overwriting of bootloader binary
	if (flash->size < MIN_OFFSET_FROM_START + FLASH_PARAMS_OFFSET_FROM_END)
	{
		printf("Invalid flash size: %u\n", flash->size);
		return NULL;
	}

	return flash;
}

static int write_params_to_flash(struct spi_nor *flash, uint32_t flash_params_offset,
								 const struct flash_params *flash_params)
{
	int ret = 0;

	uint32_t erase_blocks = sizeof(*flash_params) / flash->erase_size;
	if (sizeof(struct flash_params) % flash->erase_size)
		++erase_blocks;

	ret = spi_flash_erase(flash, flash_params_offset, erase_blocks * flash->erase_size);
	if (ret != 0)
		return ret;

	ret = spi_flash_write(flash, flash_params_offset, sizeof(*flash_params), flash_params);

	return ret;
}

static int validate_flash_params(struct flash_params *flash_params, int validate_modified)
{
	int ret = 0;

	const char *prefix = validate_modified ? "fastboot.validate_err_modified_" : "fastboot.validate_err_loaded_";
	const char *feedback = NULL;

	if (check_serial_number(flash_params->serial_number) != 0)
	{
		set_fb_env_var(prefix, "serial_number", "invalid");

		ret = 1;
		if (!validate_modified)
			memset(flash_params->serial_number, 0, sizeof(flash_params->serial_number));
	}

	if (check_ethernet_settings(&flash_params->ethernet_settings, &feedback) != 0)
	{
		if (!feedback)
			feedback = "invalid";
		set_fb_env_var(prefix, "eth_settings", feedback);

		ret = 1;
		if (!validate_modified)
			write_default_ethernet_settings(&flash_params->ethernet_settings);
	}

	if (check_emmc_layout(&flash_params->emmc_layout, &feedback) != 0)
	{
		if (!feedback)
			feedback = "invalid";
		set_fb_env_var(prefix, "emmc_layout", feedback);

		ret = 1;
		if (!validate_modified)
			write_default_emmc_layout(&flash_params->emmc_layout);
	}

	if (flash_params->board_boot_policy >= BOARD_BOOT_POLICY_COUNT)
	{
		set_fb_env_var(prefix, "board_boot_policy", "invalid");

		ret = 1;
		if (!validate_modified)
		{
			flash_params->board_boot_policy = BOARD_BOOT_POLICY_NOT_SET;
			flash_params->project_id = 0;
		}
	}

	return ret;
}

static int init_device_flash_params(void)
{
	struct spi_nor *flash = probe_flash();
	if (!flash)
	{
		return 1;
	}

	int param_offset = get_flash_params_offset(flash);
	if (spi_flash_read(flash, param_offset, sizeof(device_flash_params), &device_flash_params) != 0)
	{
		printf("Failed to read flash params (%u bytes) from flash addr: %u\n",
			   sizeof(device_flash_params), param_offset);
		return 1;
	}

	validate_flash_params(&device_flash_params, 0);

	return 0;
}

int check_serial_number(const char buf[sizeof(((struct flash_params *)0)->serial_number)])
{
	// Serial number must be made up of printable characters and null-terminated
	for (int i = 0; i < sizeof(((struct flash_params *)0)->serial_number); ++i)
	{
		if (buf[i] == 0)
			return 0;
		if (buf[i] < 0x20 || buf[i] > 0x7e)
			return 1;
	}

	return 1;
}

int init_from_spi_flash(void)
{
	if (init_device_flash_params() != 0)
	{
		panic("initialization of flash memory device parameters failed");
		return 1;
	}

	apply_ethernet_settings(&device_flash_params.ethernet_settings);

	modified_device_flash_params = device_flash_params;

	const char *boot_policy_desc = boot_policy_attributes[device_flash_params.board_boot_policy].description;
	char mac_str[MAC_IP_ADDR_STR_LEN];
	char ip_str[MAC_IP_ADDR_STR_LEN];
	char netmask_str[MAC_IP_ADDR_STR_LEN];

	snprintf(mac_str, sizeof(mac_str), "%pM", device_flash_params.ethernet_settings.mac_address);
	ip_to_string(device_flash_params.ethernet_settings.ip_address, ip_str);
	ip_to_string(device_flash_params.ethernet_settings.netmask, netmask_str);

	printf("Read device parameters from SPI flash:\n"
		   "\tBoard boot policy: %u (%s)\n"
		   "\tProject ID: %#010x\n"
		   "\tSerial #: %s\n"
		   "\tNetwork configuration:\n"
		   "\t\tMAC address: %s\n"
		   "\t\tIP address: %s\n"
		   "\t\tNetmask: %s\n"
		   "\tEMMC layout:\n"
		   "\t\tDevice state addr: %#010x\n"
		   "\t\tRecovery addr: %#010x\n"
		   "\t\tRecovery size: %#010x\n"
		   "\t\tSoftware addr: %#010x\n"
		   "\t\tSoftware size: %#010x\n\n",
		   device_flash_params.board_boot_policy, boot_policy_desc, device_flash_params.project_id, device_flash_params.serial_number,
		   mac_str, ip_str, netmask_str, device_flash_params.emmc_layout.state_addr,
		   device_flash_params.emmc_layout.recovery_addr, device_flash_params.emmc_layout.recovery_size,
		   device_flash_params.emmc_layout.software_addr, device_flash_params.emmc_layout.software_size);

	return 0;
}

int write_modified_flash_params(void)
{
	struct spi_nor *flash = probe_flash();
	if (!flash)
	{
		return 1;
	}

	if (validate_flash_params(&modified_device_flash_params, 1) != 0)
	{
		printf("Validation of modified flash params failed\n");
		return 1;
	}

	int param_offset = get_flash_params_offset(flash);
	if (write_params_to_flash(flash, param_offset, &modified_device_flash_params) != 0)
	{
		printf("Writeback of flash_params to flash addr %u failed\n", param_offset);
		return 1;
	}

	device_flash_params = modified_device_flash_params;

	return 0;
}

void initialize_fb_env_from_loaded_params(void)
{
	set_env_variables_from_params(&device_flash_params, 0);
}
