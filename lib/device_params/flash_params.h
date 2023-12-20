// SPDX-License-Identifier: GPL-2.0+
#ifndef DEVICE_PARAMS_FLASH_PARAMS_H
#define DEVICE_PARAMS_FLASH_PARAMS_H

#include <device_params.h>

int check_serial_number(const char buf[sizeof(((struct flash_params *)0)->serial_number)]);
int init_from_spi_flash(void);
int write_modified_flash_params(void);
void initialize_fb_env_from_loaded_params(void);

extern struct flash_params device_flash_params;
extern struct flash_params modified_device_flash_params;

#endif // DEVICE_PARAMS_FLASH_PARAMS_H
