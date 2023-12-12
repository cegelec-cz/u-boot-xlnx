// SPDX-License-Identifier: GPL-2.0+
/*
 * Command for reading and writing persistent device parameters in SPI flash
 *
 * Copyright (c) 2023 - Cegelec a.s.
 */

#include <blk.h>
#include <cassert.h>
#include <command.h>
#include <common.h>
#include <env.h>
#include <net.h>
#include <part.h>
#include <spi_flash.h>
#include <stdint.h>
#include <u-boot/crc.h>
#include <device_params.h>
#include <boot_policy.h>

#define MAX_UINT32 0xFFFFFFFFUL
#define MAC_IP_ADDR_STR_LEN 20

#define MIN_OFFSET_FROM_START 5242880UL		   // 5 MiB
#define FLASH_PARAMS_OFFSET_FROM_END 1048576UL // 1 MiB

// Check overlap of state <-> backup, state <-> software and backup <-> software partitions
#define CHECK_EMMC_OVERLAP(state_start, state_size,               \
						   backup_start, backup_size,             \
						   software_start, software_size)         \
	(                                                             \
		((state_start) < ((backup_start) + (backup_size)) &&      \
		 (backup_start) < ((state_start) + (state_size))) ||      \
		((state_start) < ((software_start) + (software_size)) &&  \
		 (software_start) < ((state_start) + (state_size))) ||    \
		((backup_start) < ((software_start) + (software_size)) && \
		 (software_start) < ((backup_start) + (backup_size))))

typedef enum
{
	DEVPARAMS_ERR_NONE,
	DEVPARAMS_ERR_ETH_SETTINGS_BAD_CRC,
	DEVPARAMS_ERR_ETH_SETTINGS_INVALID_MAC,
	DEVPARAMS_ERR_ETH_SETTINGS_INVALID_IPADDR,
	DEVPARAMS_ERR_ETH_SETTINGS_INVALID_NETMASK,
	DEVPARAMS_ERR_EMMC_LAYOUT_BAD_CRC,
	DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_STATE_SIZE,
	DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_BACKUP_SIZE,
	DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_SW_SIZE,
	DEVPARAMS_ERR_EMMC_LAYOUT_OVERLAP,
	DEVPARAMS_ERR_COUNT
} device_params_err_t;

static const char *err_feedback[DEVPARAMS_ERR_COUNT] = {
	[DEVPARAMS_ERR_NONE] = "",
	[DEVPARAMS_ERR_ETH_SETTINGS_BAD_CRC] = "ethernet settings: CRC check failed",
	[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_MAC] = "ethernet settings: invalid MAC address",
	[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_IPADDR] = "ethernet settings: invalid IP address",
	[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_NETMASK] = "ethernet settings: invalid netmask",
	[DEVPARAMS_ERR_EMMC_LAYOUT_BAD_CRC] = "emmc layout: CRC check failed",
	[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_STATE_SIZE] = "emmc layout: invalid state partition size",
	[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_BACKUP_SIZE] = "emmc layout: invalid backup partition size",
	[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_SW_SIZE] = "emmc layout: invalid software partition size",
	[DEVPARAMS_ERR_EMMC_LAYOUT_OVERLAP] = "emmc layout: partitions overlap emmc_state or each other",
};

static struct
{
	const char *identifier;
	const char *description;
} boot_policy_attributes[BOARD_BOOT_POLICY_COUNT] = {
	[BOARD_BOOT_POLICY_NOT_SET] =
		{.identifier = "unset", .description = "boot policy not set - boot is disabled until boot policy is configured"},
	[BOARD_BOOT_POLICY_PRODUCTION] =
		{.identifier = "production", .description = "production board - boots only signed release firmware with correct project ID"},
	[BOARD_BOOT_POLICY_SIGNED] =
		{.identifier = "signed", .description = "signed board - boots any signed firmware with correct project ID"},
	[BOARD_BOOT_POLICY_DEVELOPMENT_PROJECT_ID] =
		{.identifier = "development_with_project_id_check", .description = "development board - boots signed and unsigned firmware with correct project ID"},
	[BOARD_BOOT_POLICY_DEVELOPMENT] =
		{.identifier = "development_no_project_id_check", .description = "(dangerous) development board - boots signed and unsigned firmware with any project ID"},
};

// Compile-time check that flash_params fit into last 1MiB
CASSERT(sizeof(struct flash_params) < FLASH_PARAMS_OFFSET_FROM_END);

static const struct emmc_layout default_emmc_layout = {
	.state_addr = DEFAULT_EMMC_STATE_ADDR,
	.state_size = DEFAULT_EMMC_STATE_SIZE,
	.backup_addr = DEFAULT_EMMC_BACKUP_ADDR,
	.backup_size = DEFAULT_EMMC_BACKUP_SIZE,
	.software_addr = DEFAULT_EMMC_SOFTWARE_ADDR,
	.software_size = DEFAULT_EMMC_SOFTWARE_SIZE,
	.crc = 0,
};
// Compile-time check of default emmc layout validity
CASSERT(
	DEFAULT_EMMC_STATE_SIZE >= sizeof(struct emmc_state) &&
	DEFAULT_EMMC_BACKUP_SIZE >= MAX_SW_BLOB_SIZE &&
	DEFAULT_EMMC_SOFTWARE_SIZE >= MAX_SW_BLOB_SIZE &&
	!CHECK_EMMC_OVERLAP(DEFAULT_EMMC_STATE_ADDR,
						DEFAULT_EMMC_STATE_SIZE,
						DEFAULT_EMMC_BACKUP_ADDR,
						DEFAULT_EMMC_BACKUP_SIZE,
						DEFAULT_EMMC_SOFTWARE_ADDR,
						DEFAULT_EMMC_SOFTWARE_SIZE));

struct flash_params device_flash_params;
struct flash_params modified_device_flash_params;

uint32_t compute_ethernet_settings_crc(const struct ethernet_settings *ethernet_settings)
{
	return crc32(0, (const uint8_t *)ethernet_settings,
				 sizeof(*ethernet_settings) - sizeof(ethernet_settings->crc));
}

uint32_t compute_emmc_layout_crc(const struct emmc_layout *emmc_layout)
{
	return crc32(0, (const uint8_t *)emmc_layout,
				 sizeof(*emmc_layout) - sizeof(emmc_layout->crc));
}

int check_ethernet_settings(const struct ethernet_settings *ethernet_settings, const char **feedback)
{
	int ret = 0;
	const char *feedback_str = NULL;

	if (ethernet_settings->crc != compute_ethernet_settings_crc(ethernet_settings))
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_ETH_SETTINGS_BAD_CRC];
		ret = 1;
	}
	else if (!is_valid_ethaddr(ethernet_settings->mac_address))
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_MAC];
		ret = 1;
	}
	else if (ethernet_settings->ip_address.s_addr == 0 ||
			 ethernet_settings->ip_address.s_addr == MAX_UINT32)
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_IPADDR];
		ret = 1;
	}
	else if (ethernet_settings->netmask.s_addr == 0 ||
			 ethernet_settings->netmask.s_addr == MAX_UINT32)
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_ETH_SETTINGS_INVALID_NETMASK];
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

int check_emmc_layout(const struct emmc_layout *emmc_layout, const char **feedback)
{
	int ret = 0;
	const char *feedback_str = NULL;

	if (emmc_layout->crc != compute_emmc_layout_crc(emmc_layout))
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_EMMC_LAYOUT_BAD_CRC];
		ret = 1;
	}
	else if (emmc_layout->state_size < sizeof(struct emmc_state))
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_STATE_SIZE];
		ret = 1;
	}
	else if (emmc_layout->backup_size < MAX_SW_BLOB_SIZE)
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_BACKUP_SIZE];
		ret = 1;
	}
	else if (emmc_layout->software_size < MAX_SW_BLOB_SIZE)
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_EMMC_LAYOUT_INVALID_SW_SIZE];
		ret = 1;
	}
	else if (CHECK_EMMC_OVERLAP(
				 emmc_layout->state_addr,
				 emmc_layout->state_size,
				 emmc_layout->backup_addr,
				 emmc_layout->backup_size,
				 emmc_layout->software_addr,
				 emmc_layout->software_size))
	{
		feedback_str = err_feedback[DEVPARAMS_ERR_EMMC_LAYOUT_OVERLAP];
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

int get_boot_policy(const char *identifier)
{
	for (int i = 0; i < BOARD_BOOT_POLICY_COUNT; ++i)
	{
		if (strcmp(identifier, boot_policy_attributes[i].identifier) == 0)
			return i;
	}

	return -1;
}

void print_boot_policy_help(char *buf, size_t size)
{
	int cap = size;
	int count = snprintf(buf, cap, "Supported boot policies: ");
	cap -= count;
	buf += count;
	if (cap <= 0)
		return;

	for (int i = 0; i < BOARD_BOOT_POLICY_COUNT; ++i)
	{
		const char *fmt = i == BOARD_BOOT_POLICY_COUNT - 1 ? "%s" : "%s, ";
		count = snprintf(buf, cap, fmt, boot_policy_attributes[i].identifier);
		cap -= count;
		buf += count;
		if (cap <= 0)
			return;
	}
}

const char *get_boot_policy_name(board_boot_policy_t policy)
{
	return boot_policy_attributes[policy].identifier;
}

static void write_default_ethernet_settings(struct ethernet_settings *ethernet_settings)
{
	string_to_enetaddr(DEFAULT_MAC_ADDR, ethernet_settings->mac_address);
	ethernet_settings->ip_address = string_to_ip(DEFAULT_IP_ADDR);
	ethernet_settings->netmask = string_to_ip(DEFAULT_NETMASK);
	ethernet_settings->crc = compute_ethernet_settings_crc(ethernet_settings);
}

static void write_default_emmc_layout(struct emmc_layout *emmc_layout)
{
	*emmc_layout = default_emmc_layout;
	emmc_layout->crc = compute_emmc_layout_crc(emmc_layout);
}

static void apply_ethernet_settings(const struct ethernet_settings *ethernet_settings)
{
	char ip_string[MAC_IP_ADDR_STR_LEN];

	net_ip = ethernet_settings->ip_address;
	net_netmask = ethernet_settings->netmask;
	eth_env_set_enetaddr("ethaddr", ethernet_settings->mac_address);
	ip_to_string(ethernet_settings->ip_address, ip_string);
	env_set("ipaddr", ip_string);
	ip_to_string(ethernet_settings->netmask, ip_string);
	env_set("netmask", ip_string);
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

static int get_flash_params_offset(const struct spi_nor *flash)
{
	return flash->size - FLASH_PARAMS_OFFSET_FROM_END;
}

static struct spi_nor *probe_flash()
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

	int param_offset = get_flash_params_offset(flash);
	if (flash->flash_is_unlocked &&
		!flash->flash_is_unlocked(flash, param_offset, sizeof(device_flash_params)))
	{
		printf("Flash region starting at %u (size: %u) containing params is locked\n",
			   param_offset, sizeof(device_flash_params));
		return NULL;
	}

	return flash;
}

static int validate_flash_params(struct flash_params *flash_params, int set_defaults)
{
	int ret = 0;

	// Guarantee printability and null-termination of serial # in case of corrupt flash data
	if (check_serial_number(flash_params->serial_number) != 0)
	{
		ret = 1;
		if (!set_defaults)
			return ret;

		printf("Invalid device serial number detected, clearing serial number\n");
		memset(flash_params->serial_number, 0, sizeof(flash_params->serial_number));
	}

	if (check_ethernet_settings(&flash_params->ethernet_settings, NULL) != 0)
	{
		ret = 1;
		if (!set_defaults)
			return ret;

		printf("Invalid ethernet settings detected, writing default settings\n");
		write_default_ethernet_settings(&flash_params->ethernet_settings);
	}

	if (check_emmc_layout(&flash_params->emmc_layout, NULL) != 0)
	{
		ret = 1;
		if (!set_defaults)
			return ret;

		printf("Invalid EMMC layout detected, writing default settings\n");
		write_default_emmc_layout(&flash_params->emmc_layout);
	}

	if (flash_params->board_boot_policy >= BOARD_BOOT_POLICY_COUNT)
	{
		ret = 1;
		if (!set_defaults)
			return ret;

		printf("Invalid board boot policy detected, clearing board boot policy and project ID\n");
		flash_params->board_boot_policy = BOARD_BOOT_POLICY_NOT_SET;
		flash_params->project_id = 0;
	}

	return ret;
}

struct blk_desc *mmc_get_device_params_dev()
{
	struct blk_desc *ret = blk_get_dev("mmc",
									   DEVICE_PARAMS_MMC_DEV);

	if (!ret || ret->type == DEV_TYPE_UNKNOWN)
	{
		printf("Invalid MMC device\n");
		return NULL;
	}
	return ret;
}

static int init_device_flash_params()
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

	int write_flash = validate_flash_params(&device_flash_params, 1) != 0;
	if (write_flash &&
		write_params_to_flash(flash, param_offset, &device_flash_params) != 0)
	{
		printf("Writeback of flash_params to flash addr %u failed\n", param_offset);
		return 1;
	}

	return 0;
}

static int get_emmc_state_internal(uint32_t state_addr, struct emmc_state *emmc_state)
{
	struct blk_desc *mmc = mmc_get_device_params_dev();
	if (!mmc)
	{
		return 1;
	}

	uint8_t buf[DEVICE_PARAMS_MMC_BLKSIZE];
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

	uint8_t buf[DEVICE_PARAMS_MMC_BLKSIZE];
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

int init_from_spi_flash()
{
	if (init_device_flash_params() != 0)
		return 1;

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
		   device_flash_params.emmc_layout.backup_addr, device_flash_params.emmc_layout.backup_size,
		   device_flash_params.emmc_layout.software_addr, device_flash_params.emmc_layout.software_size);

	return 0;
}

int write_modified_flash_params()
{
	struct spi_nor *flash = probe_flash();
	if (!flash)
	{
		return 1;
	}

	if (validate_flash_params(&modified_device_flash_params, 0) != 0)
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
