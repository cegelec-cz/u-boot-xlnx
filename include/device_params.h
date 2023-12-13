#ifndef __DEVICE_PARAMS_H
#define __DEVICE_PARAMS_H

#include <net.h>
#include <boot_policy.h>

enum sw_state_t
{
    SW_STATE_EMPTY,
    SW_STATE_FASTBOOT,
    SW_STATE_UPDATED,
    SW_STATE_STARTED,
    SW_STATE_FAILED,
    SW_STATE_VALID,
    SW_STATE_COUNT
};

struct ethernet_settings
{
    uint8_t mac_address[6];
    struct in_addr ip_address;
    struct in_addr netmask;
    uint32_t crc;
} __attribute__((__packed__));

struct emmc_layout
{
    uint32_t state_addr;
    uint32_t state_size;
    uint32_t recovery_addr;
    uint32_t recovery_size;
    uint32_t software_addr;
    uint32_t software_size;
    uint32_t crc;
} __attribute__((__packed__));

struct emmc_state
{
    uint32_t sw_state;
} __attribute__((__packed__));

// Persistent device parameters in flash
struct flash_params
{
    board_boot_policy_t board_boot_policy;
    uint32_t project_id;
    unsigned char serial_number[200];
    struct ethernet_settings ethernet_settings;
    struct emmc_layout emmc_layout;
} __attribute__((__packed__));

extern struct flash_params device_flash_params;
extern struct flash_params modified_device_flash_params;

uint32_t compute_ethernet_settings_crc(const struct ethernet_settings *ethernet_settings);
uint32_t compute_emmc_layout_crc(const struct emmc_layout *emmc_layout);
int check_ethernet_settings(const struct ethernet_settings *ethernet_settings, const char **feedback);
int check_emmc_layout(const struct emmc_layout *emmc_layout, const char **feedback);
int check_serial_number(const char buf[sizeof(((struct flash_params *)0)->serial_number)]);
int get_boot_policy(const char *identifier);
void print_boot_policy_help(char *buf, size_t size);
const char *get_boot_policy_name(board_boot_policy_t policy);

struct blk_desc *mmc_get_device_params_dev();
int get_emmc_state(struct emmc_state *emmc_state);
int write_emmc_state(const struct emmc_state *emmc_state);

int init_from_spi_flash();
int write_modified_flash_params();

#endif // __DEVICE_PARAMS_H
