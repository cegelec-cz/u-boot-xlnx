// SPDX-License-Identifier: GPL-2.0+
#include "fb_env_vars.h"

#include "dp_boot_policy_helpers.h"

#include <env.h>
#include <device_params.h>

#define MAC_IP_ADDR_STR_LEN 20

void set_fb_env_var(const char *prefix, const char *name, const char *fmt_val, ...)
{
	prefix = (prefix == NULL) ? "fastboot." : prefix;

	char name_buf[128];
	char value_buf[128];

	snprintf(name_buf, sizeof(name_buf), "%s%s", prefix, name);

	va_list args;
	va_start(args, fmt_val);
	vsnprintf(value_buf, sizeof(value_buf), fmt_val, args);
	va_end(args);

	env_set(name_buf, value_buf);
}

void set_env_variables_from_params(const struct flash_params *params, int modified_params)
{
	const char *prefix = modified_params ? "fastboot.modified_" : "fastboot.";

	set_fb_env_var(prefix, "board_boot_policy", "%s (%s)",
				   get_boot_policy_name(params->board_boot_policy),
				   get_boot_policy_description(params->board_boot_policy));
	set_fb_env_var(prefix, "project_id", "%#010x", params->project_id);
	set_fb_env_var(prefix, "serial_number", params->serial_number);

	set_fb_env_var(prefix, "mac_addr", "%pM", params->ethernet_settings.mac_address);
	char buf[MAC_IP_ADDR_STR_LEN];
	ip_to_string(params->ethernet_settings.ip_address, buf);
	set_fb_env_var(prefix, "ip_addr", buf);
	ip_to_string(params->ethernet_settings.netmask, buf);
	set_fb_env_var(prefix, "netmask", buf);

	set_fb_env_var(prefix, "emmc_state_addr", "%#010x", params->emmc_layout.state_addr);
	set_fb_env_var(prefix, "emmc_recovery_addr", "%#010x", params->emmc_layout.recovery_addr);
	set_fb_env_var(prefix, "emmc_recovery_size", "%#010x", params->emmc_layout.recovery_size);
	set_fb_env_var(prefix, "emmc_software_addr", "%#010x", params->emmc_layout.software_addr);
	set_fb_env_var(prefix, "emmc_software_size", "%#010x", params->emmc_layout.software_size);
}
