// SPDX-License-Identifier: GPL-2.0+
#ifndef DEVICE_PARAMS_FB_ENV_VARS_H
#define DEVICE_PARAMS_FB_ENV_VARS_H

#include <device_params.h>

void set_fb_env_var(const char *prefix, const char *name, const char *fmt_val, ...)
	__attribute__((format(__printf__, 3, 4)));
void set_env_variables_from_params(const struct flash_params *params, int modified_params);

#endif // DEVICE_PARAMS_FB_ENV_VARS_H
