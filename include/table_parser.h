#pragma once

// #include <stdint.h>

#include "skel.h"

#define ROW_LEN 45
#define ARP_ROW_LEN 30
#define IP_BUFF_LEN 30

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
}__attribute__((packed));

int read_rtable(struct route_table_entry *rtable, char *file_name);
int read_arp_table(struct arp_entry *arp_table, char *file_name);