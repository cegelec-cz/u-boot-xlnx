// SPDX-License-Identifier: GPL-2.0+
#ifndef DEVICE_PARAMS_DP_BOOT_POLICY_HELPERS_H
#define DEVICE_PARAMS_DP_BOOT_POLICY_HELPERS_H

#include <boot_policy.h>
#include <common.h>

board_boot_policy_t get_boot_policy(const char *identifier);
const char *get_boot_policy_name(board_boot_policy_t policy);
const char *get_boot_policy_description(board_boot_policy_t policy);
void print_boot_policy_help(char *buf, size_t size);

#endif // DEVICE_PARAMS_DP_BOOT_POLICY_HELPERS_H
