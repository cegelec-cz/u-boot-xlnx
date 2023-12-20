// SPDX-License-Identifier: GPL-2.0+
#ifndef DEVICE_PARAMS_ETHERNET_SETTINGS_H
#define DEVICE_PARAMS_ETHERNET_SETTINGS_H

#include <device_params.h>
#include <linux/types.h>

void write_default_ethernet_settings(struct ethernet_settings *ethernet_settings);
void apply_ethernet_settings(const struct ethernet_settings *ethernet_settings);
uint32_t compute_ethernet_settings_crc(const struct ethernet_settings *ethernet_settings);
int check_ethernet_settings(const struct ethernet_settings *ethernet_settings, const char **feedback);

#endif // DEVICE_PARAMS_ETHERNET_SETTINGS_H
