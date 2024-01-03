// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Cegelec a.s.
 */

#include <common.h>
#include <command.h>
#include <net.h>

static int do_hardflash_request(struct cmd_tbl *cmdtp, int flag, int argc,
								char *const argv[])
{
#if CONFIG_IS_ENABLED(HARDFLASH_REQUEST)
	int err = net_loop(HARDFLASH_REQUEST);

	if (err < 0)
	{
		printf("hardflash request error: %d\n", err);
		return CMD_RET_FAILURE;
	}

	return CMD_RET_SUCCESS;
#else
	pr_err("Hardflash request not enabled\n");
	return CMD_RET_FAILURE;
#endif
}

U_BOOT_CMD(
	process_hardflash_request, 1, 0, do_hardflash_request,
	"wait for and process hardflash request", "");
