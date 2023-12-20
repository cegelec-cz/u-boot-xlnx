// SPDX-License-Identifier: GPL-2.0+
#include "dp_boot_policy_helpers.h"

#include <boot_policy.h>
#include <common.h>

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

board_boot_policy_t get_boot_policy(const char *identifier)
{
	for (int i = 0; i < BOARD_BOOT_POLICY_COUNT; ++i)
	{
		if (strcmp(identifier, boot_policy_attributes[i].identifier) == 0)
			return i;
	}

	return -1;
}

const char *get_boot_policy_name(board_boot_policy_t policy)
{
	if (policy >= BOARD_BOOT_POLICY_COUNT)
		return NULL;

	return boot_policy_attributes[policy].identifier;
}

const char *get_boot_policy_description(board_boot_policy_t policy)
{
	if (policy >= BOARD_BOOT_POLICY_COUNT)
		return NULL;

	return boot_policy_attributes[policy].description;
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
