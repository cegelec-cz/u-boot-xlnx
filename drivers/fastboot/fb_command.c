// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 The Android Open Source Project
 */

#include <common.h>
#include <command.h>
#include <env.h>
#include <fastboot.h>
#include <fastboot-internal.h>
#include <fb_mmc.h>
#include <fb_nand.h>
#include <part.h>
#include <stdlib.h>
#include <device_params.h>
#include <vsprintf.h>

/**
 * image_size - final fastboot image size
 */
static u32 image_size;

/**
 * fastboot_bytes_received - number of bytes received in the current download
 */
static u32 fastboot_bytes_received;

/**
 * fastboot_bytes_expected - number of bytes expected in the current download
 */
static u32 fastboot_bytes_expected;

static void run_privileged_command(char *, char *, void (*)(char *, char *));

static void okay(char *, char *);
static void getvar(char *, char *);
static void download(char *, char *);
static void flash(char *, char *);
static void erase(char *, char *);
static void unlock(char *, char *);
static void commit(char *, char *);
static void set_mac_addr(char *, char *);
static void set_ip_addr(char *, char *);
static void set_netmask(char *, char *);
static void set_serial_number(char *, char *);
static void set_project_id(char *, char *);
static void set_board_boot_policy(char *, char *);
static void set_emmc_layout(char *, char *);

static const struct
{
	const char *command;
	void (*dispatch)(char *cmd_parameter, char *response);
	int privileged;
} commands[FASTBOOT_COMMAND_COUNT] = {
	[FASTBOOT_COMMAND_GETVAR] = {
		.command = "getvar",
		.dispatch = getvar},
	[FASTBOOT_COMMAND_DOWNLOAD] = {.command = "download", .dispatch = download},
	[FASTBOOT_COMMAND_FLASH] = {.command = "flash", .dispatch = flash},
	[FASTBOOT_COMMAND_ERASE] = {.command = "erase", .dispatch = erase},
	[FASTBOOT_COMMAND_BOOT] = {.command = "boot", .dispatch = okay},
	[FASTBOOT_COMMAND_REBOOT] = {.command = "reboot", .dispatch = okay},
	[FASTBOOT_COMMAND_OEM_UNLOCK] = {.command = "oem unlock", .dispatch = unlock},
	[FASTBOOT_COMMAND_OEM_COMMIT] = {.command = "oem commit", .dispatch = commit, .privileged = 1},
	[FASTBOOT_COMMAND_OEM_SET_MAC_ADDR] = {.command = "oem set_mac_addr", .dispatch = set_mac_addr, .privileged = 1},
	[FASTBOOT_COMMAND_OEM_SET_IP_ADDR] = {.command = "oem set_ip_addr", .dispatch = set_ip_addr, .privileged = 1},
	[FASTBOOT_COMMAND_OEM_SET_NETMASK] = {.command = "oem set_netmask", .dispatch = set_netmask, .privileged = 1},
	[FASTBOOT_COMMAND_OEM_SET_SERIAL_NUMBER] = {.command = "oem set_serial_number", .dispatch = set_serial_number, .privileged = 1},
	[FASTBOOT_COMMAND_OEM_SET_PROJECT_ID] = {.command = "oem set_project_id", .dispatch = set_project_id, .privileged = 1},
	[FASTBOOT_COMMAND_OEM_SET_BOARD_BOOT_POLICY] = {.command = "oem set_board_boot_policy", .dispatch = set_board_boot_policy, .privileged = 1},
	[FASTBOOT_COMMAND_OEM_SET_EMMC_LAYOUT] = {.command = "oem set_emmc_layout", .dispatch = set_emmc_layout, .privileged = 1},
};

static void run_privileged_command(char *cmd_parameter, char *response,
								   void (*dispatch)(char *, char *))
{
	// TODO: implement bootloader unlock mechanism
	if (device_flash_params.board_boot_policy != BOARD_BOOT_POLICY_NOT_SET)
	{
		fastboot_fail("Execution of privileged command not authorized", response);
		return;
	}

	dispatch(cmd_parameter, response);
}

/**
 * fastboot_handle_command - Handle fastboot command
 *
 * @cmd_string: Pointer to command string
 * @response: Pointer to fastboot response buffer
 *
 * Return: Executed command, or -1 if not recognized
 */
int fastboot_handle_command(char *cmd_string, char *response)
{
	int i;
	char *cmd_parameter;

	cmd_parameter = cmd_string;
	strsep(&cmd_parameter, ":");

	for (i = 0; i < FASTBOOT_COMMAND_COUNT; i++)
	{
		if (!strcmp(commands[i].command, cmd_string))
		{
			if (commands[i].dispatch)
			{
				if (commands[i].privileged)
				{
					run_privileged_command(cmd_parameter, response, commands[i].dispatch);
				}
				else
				{
					commands[i].dispatch(cmd_parameter, response);
				}

				return i;
			}
			else
			{
				break;
			}
		}
	}

	pr_err("command %s not recognized.\n", cmd_string);
	fastboot_fail("unrecognized command", response);
	return -1;
}

/**
 * okay() - Send bare OKAY response
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 *
 * Send a bare OKAY fastboot response. This is used where the command is
 * valid, but all the work is done after the response has been sent (e.g.
 * boot, reboot etc.)
 */
static void okay(char *cmd_parameter, char *response)
{
	fastboot_okay(NULL, response);
}

/**
 * getvar() - Read a config/version variable
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void getvar(char *cmd_parameter, char *response)
{
	fastboot_getvar(cmd_parameter, response);
}

/**
 * fastboot_download() - Start a download transfer from the client
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void download(char *cmd_parameter, char *response)
{
	char *tmp;

	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}
	fastboot_bytes_received = 0;
	fastboot_bytes_expected = hextoul(cmd_parameter, &tmp);
	if (fastboot_bytes_expected == 0)
	{
		fastboot_fail("Expected nonzero image size", response);
		return;
	}
	/*
	 * Nothing to download yet. Response is of the form:
	 * [DATA|FAIL]$cmd_parameter
	 *
	 * where cmd_parameter is an 8 digit hexadecimal number
	 */
	if (fastboot_bytes_expected > fastboot_buf_size)
	{
		fastboot_fail(cmd_parameter, response);
	}
	else
	{
		printf("Starting download of %d bytes\n",
			   fastboot_bytes_expected);
		fastboot_response("DATA", response, "%s", cmd_parameter);
	}
}

/**
 * fastboot_data_remaining() - return bytes remaining in current transfer
 *
 * Return: Number of bytes left in the current download
 */
u32 fastboot_data_remaining(void)
{
	return fastboot_bytes_expected - fastboot_bytes_received;
}

/**
 * fastboot_data_download() - Copy image data to fastboot_buf_addr.
 *
 * @fastboot_data: Pointer to received fastboot data
 * @fastboot_data_len: Length of received fastboot data
 * @response: Pointer to fastboot response buffer
 *
 * Copies image data from fastboot_data to fastboot_buf_addr. Writes to
 * response. fastboot_bytes_received is updated to indicate the number
 * of bytes that have been transferred.
 *
 * On completion sets image_size and ${filesize} to the total size of the
 * downloaded image.
 */
void fastboot_data_download(const void *fastboot_data,
							unsigned int fastboot_data_len,
							char *response)
{
#define BYTES_PER_DOT 0x20000
	u32 pre_dot_num, now_dot_num;

	if (fastboot_data_len == 0 ||
		(fastboot_bytes_received + fastboot_data_len) >
			fastboot_bytes_expected)
	{
		fastboot_fail("Received invalid data length",
					  response);
		return;
	}
	/* Download data to fastboot_buf_addr */
	memcpy(fastboot_buf_addr + fastboot_bytes_received,
		   fastboot_data, fastboot_data_len);

	pre_dot_num = fastboot_bytes_received / BYTES_PER_DOT;
	fastboot_bytes_received += fastboot_data_len;
	now_dot_num = fastboot_bytes_received / BYTES_PER_DOT;

	if (pre_dot_num != now_dot_num)
	{
		putc('.');
		if (!(now_dot_num % 74))
			putc('\n');
	}
	*response = '\0';
}

/**
 * fastboot_data_complete() - Mark current transfer complete
 *
 * @response: Pointer to fastboot response buffer
 *
 * Set image_size and ${filesize} to the total size of the downloaded image.
 */
void fastboot_data_complete(char *response)
{
	/* Download complete. Respond with "OKAY" */
	fastboot_okay(NULL, response);
	printf("\ndownloading of %d bytes finished\n", fastboot_bytes_received);
	image_size = fastboot_bytes_received;
	env_set_hex("filesize", image_size);
	fastboot_bytes_expected = 0;
	fastboot_bytes_received = 0;
}

/**
 * flash() - write the downloaded image to the indicated partition.
 *
 * @cmd_parameter: Pointer to partition name
 * @response: Pointer to fastboot response buffer
 *
 * Writes the previously downloaded image to the partition indicated by
 * cmd_parameter. Writes to response.
 */
static void flash(char *cmd_parameter, char *response)
{
	fastboot_mmc_flash_write(cmd_parameter, fastboot_buf_addr, image_size,
							 response);
}

/**
 * erase() - erase the indicated partition.
 *
 * @cmd_parameter: Pointer to partition name
 * @response: Pointer to fastboot response buffer
 *
 * Erases the partition indicated by cmd_parameter (clear to 0x00s). Writes
 * to response.
 */
static void erase(char *cmd_parameter, char *response)
{
	fastboot_mmc_erase(cmd_parameter, response);
}

/**
 * reboot_bootloader() - Sets reboot bootloader flag.
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void reboot_bootloader(char *cmd_parameter, char *response)
{
	if (fastboot_set_reboot_flag(FASTBOOT_REBOOT_REASON_BOOTLOADER))
		fastboot_fail("Cannot set reboot flag", response);
	else
		fastboot_okay(NULL, response);
}

/**
 * reboot_fastbootd() - Sets reboot fastboot flag.
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void reboot_fastbootd(char *cmd_parameter, char *response)
{
	if (fastboot_set_reboot_flag(FASTBOOT_REBOOT_REASON_FASTBOOTD))
		fastboot_fail("Cannot set fastboot flag", response);
	else
		fastboot_okay(NULL, response);
}

static void unlock(char *cmd_parameter, char *response)
{
	// TODO: implement
	fastboot_fail(NULL, response);
}

static void commit(char *cmd_parameter, char *response)
{
	if (write_modified_flash_params() != 0)
	{
		fastboot_fail("Writeback of modified flash parameters failed", response);
		return;
	}

	fastboot_okay("Writeback of flash parameters successful. Modifications to ethernet settings will take place after reset", response);
}

static void set_mac_addr(char *cmd_parameter, char *response)
{
	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}

	struct ethernet_settings ethernet_settings =
		modified_device_flash_params.ethernet_settings;

	const size_t size = sizeof(ethernet_settings.mac_address);
	int res = 1;
	char *endptr = cmd_parameter;
	for (int i = 0; i < size && *endptr != '\0'; ++i)
	{
		uint32_t val = simple_strtoul(cmd_parameter, &endptr, 16);

		const char exp_end = (i == size - 1) ? '\0' : ':';
		if (endptr == cmd_parameter || *endptr != exp_end)
			break;

		if (val > 0xff)
			break;

		ethernet_settings.mac_address[i] = val;
		cmd_parameter = endptr + 1;

		if (i == size - 1)
			res = 0;
	}

	if (res != 0)
	{
		fastboot_fail("Command parameter does not contain valid MAC address", response);
		return;
	}

	ethernet_settings.crc = compute_ethernet_settings_crc(&ethernet_settings);

	const char *err_feedback = NULL;
	if (check_ethernet_settings(&ethernet_settings, &err_feedback) != 0)
	{
		if (err_feedback)
			fastboot_response("FAIL", response, err_feedback);
		else
			fastboot_fail("Ethernet settings validation failed", response);
		return;
	}

	modified_device_flash_params.ethernet_settings = ethernet_settings;

	fastboot_response("OKAY", response, "MAC address set to %pM",
					  ethernet_settings.mac_address);
}

static void set_ip_addr(char *cmd_parameter, char *response)
{
	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}

	struct ethernet_settings ethernet_settings =
		modified_device_flash_params.ethernet_settings;

	ethernet_settings.ip_address = string_to_ip(cmd_parameter);
	ethernet_settings.crc = compute_ethernet_settings_crc(&ethernet_settings);

	const char *err_feedback = NULL;
	if (check_ethernet_settings(&ethernet_settings, &err_feedback) != 0)
	{
		if (err_feedback)
			fastboot_response("FAIL", response, err_feedback);
		else
			fastboot_fail("Ethernet settings validation failed", response);
		return;
	}

	modified_device_flash_params.ethernet_settings = ethernet_settings;

	char buf[64];
	ip_to_string(ethernet_settings.ip_address, buf);

	fastboot_response("OKAY", response, "IP address set to %s", buf);
}

static void set_netmask(char *cmd_parameter, char *response)
{
	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}

	struct ethernet_settings ethernet_settings =
		modified_device_flash_params.ethernet_settings;

	ethernet_settings.netmask = string_to_ip(cmd_parameter);
	ethernet_settings.crc = compute_ethernet_settings_crc(&ethernet_settings);

	const char *err_feedback = NULL;
	if (check_ethernet_settings(&ethernet_settings, &err_feedback) != 0)
	{
		if (err_feedback)
			fastboot_response("FAIL", response, err_feedback);
		else
			fastboot_fail("Ethernet settings validation failed", response);
		return;
	}

	modified_device_flash_params.ethernet_settings = ethernet_settings;

	char buf[64];
	ip_to_string(ethernet_settings.netmask, buf);

	fastboot_response("OKAY", response, "Netmask set to %s", buf);
}

static void set_serial_number(char *cmd_parameter, char *response)
{
	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}

	char buf[sizeof(modified_device_flash_params.serial_number)];
	strncpy(buf, cmd_parameter, sizeof(buf));
	if (check_serial_number(buf) != 0)
	{
		fastboot_fail("Serial number contains non-printable characters", response);
		return;
	}

	memcpy(modified_device_flash_params.serial_number, buf, sizeof(buf));
	fastboot_response("OKAY", response, "Serial number set to %s", buf);
}

static void set_project_id(char *cmd_parameter, char *response)
{
	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}

	unsigned long project_id;
	if (strict_strtoul(cmd_parameter, 16, &project_id) != 0)
	{
		fastboot_fail("Invalid hexadecimal Project ID", response);
		return;
	}

	modified_device_flash_params.project_id = (uint32_t)project_id;
	fastboot_response("OKAY", response, "Project ID set to %#010x", modified_device_flash_params.project_id);
}

static void set_board_boot_policy(char *cmd_parameter, char *response)
{
	char help[1024];
	print_boot_policy_help(help, sizeof(help));

	if (!cmd_parameter)
	{
		fastboot_fail(help, response);
		return;
	}

	int boot_policy = get_boot_policy(cmd_parameter);
	if (boot_policy < 0)
	{
		fastboot_fail(help, response);
		return;
	}

	modified_device_flash_params.board_boot_policy = boot_policy;
	fastboot_response("OKAY", response, "Boot policy set to: %s", get_boot_policy_name(boot_policy));
}

static void set_emmc_layout(char *cmd_parameter, char *response)
{
	const char *help = "Invalid EMMC layout input. Expecting (addresses and sizes in hex): STATE_ADDR STATE_SIZE BACKUP_ADDR BACKUP_SIZE SOFTWARE_ADDR SOFTWARE_SIZE";

	if (!cmd_parameter)
	{
		fastboot_fail(help, response);
		return;
	}

	struct emmc_layout emmc_layout;

	uint32_t *const write[] = {
		&emmc_layout.state_addr,
		&emmc_layout.state_size,
		&emmc_layout.recovery_addr,
		&emmc_layout.recovery_size,
		&emmc_layout.software_addr,
		&emmc_layout.software_size};
	const size_t count = sizeof(write) / sizeof(write[0]);

	int i = 0;
	for (; i < count; ++i)
	{
		char *endptr;
		*write[i] = simple_strtoul(cmd_parameter, &endptr, 16);
		if (endptr == cmd_parameter || *endptr != ' ')
			break;
		cmd_parameter = endptr + 1;
	}

	if (i < count - 1)
	{
		fastboot_fail(help, response);
		return;
	}

	emmc_layout.crc = compute_emmc_layout_crc(&emmc_layout);

	const char *err_feedback = NULL;
	if (check_emmc_layout(&emmc_layout, &err_feedback) != 0)
	{
		if (err_feedback)
			fastboot_response("FAIL", response, err_feedback);
		else
			fastboot_fail("EMMC layout validation failed", response);
		return;
	}

	modified_device_flash_params.emmc_layout = emmc_layout;
	fastboot_okay(NULL, response);
}

/**
 * reboot_recovery() - Sets reboot recovery flag.
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void reboot_recovery(char *cmd_parameter, char *response)
{
	if (fastboot_set_reboot_flag(FASTBOOT_REBOOT_REASON_RECOVERY))
		fastboot_fail("Cannot set recovery flag", response);
	else
		fastboot_okay(NULL, response);
}

#if CONFIG_IS_ENABLED(FASTBOOT_CMD_OEM_FORMAT)
/**
 * oem_format() - Execute the OEM format command
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void oem_format(char *cmd_parameter, char *response)
{
	char cmdbuf[32];

	if (!env_get("partitions"))
	{
		fastboot_fail("partitions not set", response);
	}
	else
	{
		sprintf(cmdbuf, "gpt write mmc %x $partitions",
				CONFIG_FASTBOOT_FLASH_MMC_DEV);
		if (run_command(cmdbuf, 0))
			fastboot_fail("", response);
		else
			fastboot_okay(NULL, response);
	}
}
#endif

#if CONFIG_IS_ENABLED(FASTBOOT_CMD_OEM_PARTCONF)
/**
 * oem_partconf() - Execute the OEM partconf command
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void oem_partconf(char *cmd_parameter, char *response)
{
	char cmdbuf[32];

	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}

	/* execute 'mmc partconfg' command with cmd_parameter arguments*/
	snprintf(cmdbuf, sizeof(cmdbuf), "mmc partconf %x %s 0",
			 CONFIG_FASTBOOT_FLASH_MMC_DEV, cmd_parameter);
	printf("Execute: %s\n", cmdbuf);
	if (run_command(cmdbuf, 0))
		fastboot_fail("Cannot set oem partconf", response);
	else
		fastboot_okay(NULL, response);
}
#endif

#if CONFIG_IS_ENABLED(FASTBOOT_CMD_OEM_BOOTBUS)
/**
 * oem_bootbus() - Execute the OEM bootbus command
 *
 * @cmd_parameter: Pointer to command parameter
 * @response: Pointer to fastboot response buffer
 */
static void oem_bootbus(char *cmd_parameter, char *response)
{
	char cmdbuf[32];

	if (!cmd_parameter)
	{
		fastboot_fail("Expected command parameter", response);
		return;
	}

	/* execute 'mmc bootbus' command with cmd_parameter arguments*/
	snprintf(cmdbuf, sizeof(cmdbuf), "mmc bootbus %x %s",
			 CONFIG_FASTBOOT_FLASH_MMC_DEV, cmd_parameter);
	printf("Execute: %s\n", cmdbuf);
	if (run_command(cmdbuf, 0))
		fastboot_fail("Cannot set oem bootbus", response);
	else
		fastboot_okay(NULL, response);
}
#endif
