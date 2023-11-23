// SPDX-License-Identifier: GPL-2.0+
/*
 * Command for reading and writing persistent device parameters
 *
 * Copyright (c) 2023 - Cegelec a.s.
 */

#include <common.h>
#include <command.h>
#include <device_params.h>

int do_device_params(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	struct spi_nor *flash = NULL;
	int rcode = 0;

	// Consume 'device_params'
	argc--;
	argv++;

	if (argc >= 1 && strncmp(argv[0], "init", 4) == 0)
	{
		// Consume 'init'
		argc--;
		argv++;

		rcode = init_from_spi_flash();
	}
	else
		return 1;

	return rcode;
}

U_BOOT_CMD(
	device_params, 2, 0, do_device_params,
	"Read and modify persistent device parameters",
	"init | set \n"
	"\t- address - FW blob at address\n"
	"\t- size - FW blob size");
