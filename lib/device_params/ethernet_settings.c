// SPDX-License-Identifier: GPL-2.0+
#include "ethernet_settings.h"

#include "dp_err_feedback.h"

#include <common.h>
#include <env.h>
#include <net.h>
#include <u-boot/crc.h>
#include <device_params.h>

#define MAC_IP_ADDR_STR_LEN 20
#define MAX_UINT32 0xFFFFFFFFUL

void write_default_ethernet_settings(struct ethernet_settings *ethernet_settings)
{
	string_to_enetaddr(CONFIG_DEFAULT_MAC_ADDR, ethernet_settings->mac_address);
	ethernet_settings->ip_address = string_to_ip(CONFIG_DEFAULT_IP_ADDR);
	ethernet_settings->netmask = string_to_ip(CONFIG_DEFAULT_NETMASK);
	ethernet_settings->crc = compute_ethernet_settings_crc(ethernet_settings);
}

void apply_ethernet_settings(const struct ethernet_settings *ethernet_settings)
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

uint32_t compute_ethernet_settings_crc(const struct ethernet_settings *ethernet_settings)
{
	return crc32(0, (const uint8_t *)ethernet_settings,
				 sizeof(*ethernet_settings) - sizeof(ethernet_settings->crc));
}

int check_ethernet_settings(const struct ethernet_settings *ethernet_settings, const char **feedback)
{
	int ret = 0;
	const char *feedback_str = NULL;

	if (ethernet_settings->crc != compute_ethernet_settings_crc(ethernet_settings))
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_ETH_SETTINGS_BAD_CRC);
		ret = 1;
	}
	else if (!is_valid_ethaddr(ethernet_settings->mac_address))
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_ETH_SETTINGS_INVALID_MAC);
		ret = 1;
	}
	else if (ethernet_settings->ip_address.s_addr == 0 ||
			 ethernet_settings->ip_address.s_addr == MAX_UINT32)
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_ETH_SETTINGS_INVALID_IPADDR);
		ret = 1;
	}
	else if (ethernet_settings->netmask.s_addr == 0 ||
			 ethernet_settings->netmask.s_addr == MAX_UINT32)
	{
		feedback_str = get_dp_err_feedback(DEVPARAMS_ERR_ETH_SETTINGS_INVALID_NETMASK);
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
