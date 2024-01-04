// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Cegelec a.s.
 */

#include <cassert.h>
#include <common.h>
#include <net.h>
#include <device_params.h>

#define BEACON_TIMEOUT_MS 10
#define SENT_BEACONS 3

static const uint8_t expected_hardflash_request_magic[] = {0xa0, 0xff, 0xb0, 0xff, 0xc0, 0xff, 0xd0, 0xff, 0x0a, 0xff, 0x0b, 0xff, 0x0c, 0xff, 0x0d, 0xff};
static unsigned int hardflash_request_port = 0;
static unsigned int beacon_src_port = 0;
static unsigned int beacon_dst_port = 0;
static int hardflash_request = 0;
static ulong hardflash_timeout_ms = 0;

CASSERT(ETHER_HDR_SIZE + IP_UDP_HDR_SIZE +
			sizeof(device_flash_params.serial_number) <=
		PKTSIZE);

static void send_beacon(void)
{
	uint8_t *packet_base = net_tx_packet + net_eth_hdr_size() + IP_UDP_HDR_SIZE;
	uint8_t *packet = packet_base;

	uint32_t tmp = htonl(device_flash_params.project_id);
	memcpy(packet, &tmp, sizeof(tmp));
	packet += sizeof(tmp);

	size_t len = strnlen(device_flash_params.serial_number,
						 sizeof(device_flash_params.serial_number));
	memcpy(packet, device_flash_params.serial_number, len);
	packet += len;

	// Will be replaced by ethernet broadcast in net_send_udp_packet
	u8 eth_addr[6] = {};
	// IPv4 broadcast
	struct in_addr dst_addr = {.s_addr = 0xFFFFFFFF};

	size_t packet_len = packet - packet_base;
	net_send_udp_packet(eth_addr, dst_addr, beacon_dst_port, beacon_src_port, packet_len);
}

static void hardflash_request_handler(uchar *packet, unsigned int dport,
									  struct in_addr sip, unsigned int sport,
									  unsigned int len)
{
	if (dport != hardflash_request_port)
		return;

	if (len != sizeof(expected_hardflash_request_magic))
		return;

	if (memcmp(packet, expected_hardflash_request_magic, len) == 0)
	{
		printf("Hardflash request packet received\n");
		hardflash_request = 1;
		net_set_state(NETLOOP_SUCCESS);
	}
}

static void hardflash_request_timeout_handler(void)
{
	printf("Timed out while waiting for hardflash request\n");
	net_set_state(NETLOOP_SUCCESS);
}

static void beacon_timeout_handler(void)
{
	static unsigned int beacon_count = 0;
	++beacon_count;

	if (beacon_count > SENT_BEACONS)
	{
		net_set_timeout_handler(hardflash_timeout_ms, hardflash_request_timeout_handler);
	}
	else
	{
		send_beacon();
		net_set_timeout_handler(BEACON_TIMEOUT_MS, beacon_timeout_handler);
	}
}

int get_hardflash_request(void)
{
	return hardflash_request;
}

void start_hardflash_request_server(void)
{
	printf("Using %s device\n", eth_get_name());
	printf("Listening for hardflash request on %pI4\n", &net_ip);

	hardflash_request_port = CONFIG_HARDFLASH_REQUEST_UDP_PORT;
	// Pseudo-random src port
	beacon_src_port = 1024 + (get_timer(0) % 3072);
	beacon_dst_port = CONFIG_BEACON_UDP_DST_PORT;
	hardflash_timeout_ms = CONFIG_HARDFLASH_REQUEST_TIMEOUT;

	/* zero out server ether in case the server ip has changed */
	memset(net_server_ethaddr, 0, 6);

	net_set_timeout_handler(BEACON_TIMEOUT_MS, beacon_timeout_handler);
	net_set_udp_handler(hardflash_request_handler);

	send_beacon();
}
