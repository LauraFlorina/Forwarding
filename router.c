#include <queue.h>
#include "skel.h"
#include "table_parser.h"

#define RTABLE_LINES 100000 
#define ARP_TABLE_LINES 30

struct route_table_entry *rtable;
int rtable_size;
struct arp_entry *arp_table;
int arp_table_len;

/* 
Find best route from rtable, for a packet with destination ip = dest_ip.
Return the address of an entry in rtable.
*/
struct route_table_entry *get_best_route(__u32 dest_ip) {
	struct route_table_entry *best_route = NULL;
	int found = 0;
	for (int i = 0; i < rtable_size; i++) {
		if ((rtable[i].mask & dest_ip) == rtable[i].prefix){
			if (found == 0) {
				found = 1;
				best_route = &rtable[i];
			} else if (rtable[i].prefix > best_route->prefix) {
				best_route = &rtable[i];
			}
		}
	}
	return best_route;
}

/*
Verify if checksum is correct
Param: ip_hdr, pointer to the ip header of the packet
Return: 0 - wrong checksum
		1 - good checksum
*/
int validate_checksum(struct iphdr *ip_hdr) {
	uint16_t checksum = ip_hdr->check;
	ip_hdr->check = 0;
	uint16_t recalc_checksum = ip_checksum(ip_hdr, sizeof(struct iphdr));
	if(checksum == recalc_checksum){
		return 1;
	}
	return 0;
}

/*
Check TTL.
Param: ip_hdr, pointer to the ip header of the packet
Return: 0 - TTL exceeded
		1 - TTL good
*/
int check_ttl(struct iphdr *ip_hdr) {
	if (ip_hdr->ttl <= 1) {
		return -1;
	}
	return 0;
}


/*
Given a ip, fill in the corresponding mac from arp_table.
Return: 1 - entry with the given ip was found in the arp_table
		0 - entry with the given ip not found in the arp_table
*/
int find_mac_by_ip(uint32_t ip, uint8_t *d_mac) {
	int i;
	for (i = 0; i < arp_table_len; i++) {
		if (ip == arp_table[i].ip) {
			memcpy(d_mac, arp_table[i].mac, ETH_ALEN);
			return 1;
		}
	}
	return 0;
}

/*
Compete ethernet header.
Param: eth_hdr, pointer to the ethernet header of the packet
		best_route, entry in rtable.
*/
void complete_ethhdr(struct ether_header *eth_hdr,
	                struct route_table_entry *best_route) {
	uint8_t s_mac[6]; 
	get_interface_mac(best_route->interface, s_mac);
	uint8_t d_mac[6];
	find_mac_by_ip(best_route->next_hop, d_mac);
	build_ethhdr(eth_hdr, s_mac, d_mac, eth_hdr->ether_type);
}

/*
Recalculate checksum
Param: ip_hdr, pointer to the ip header of the packet.
*/
void recalculate_checksum(struct iphdr *ip_hdr) {
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
}

/*
Check if the packet is intended for the router.
Param: ip
Return: One of the router's interfaces, if the given ip is equal with
		the interface ip.
		-1 if the given ip does not belong to the router.
*/
int dest_reached(uint32_t ip) {
	int i = 0;
	for (i = 0; i <= ROUTER_NUM_INTERFACES; i++) {
		if (ip == inet_addr(get_interface_ip(i))) {
			return i;
		}
	}
	return -1;
}

/*
Check if an echo request has been received.
Param: ip_hdr, pointer to the ip header of the packet.
		icmp_hdr, pointer to the icmp header of the packet.
Return: 1 if true
		0 if false
*/
int check_echo_req(struct iphdr *ip_hdr, struct icmphdr *icmp_hdr) {
	if (icmp_hdr != NULL) {
		if (dest_reached(ip_hdr->daddr) != -1){
			if (icmp_hdr->type == ICMP_ECHO) {
				return 1;
			}
		}
	}
	return 0;
}

/*
Send icmp reply.
Param: ip_hdr, pointer to the ip header of the packet.
		eth_hdr, pointer to the eth header of the packet.
		icmp_hdr, pointer to the icmp header of the packet.
		m_interface, the interface where the package was received from
*/
void send_icmp_reply(struct ether_header *eth_hdr,
					struct iphdr *ip_hdr,
					struct icmphdr *icmp_hdr,
					int m_interface) {
	send_icmp(ip_hdr->saddr, ip_hdr->daddr,
		eth_hdr->ether_dhost, eth_hdr->ether_shost,
		ICMP_ECHOREPLY, 0, m_interface, icmp_hdr->un.echo.id,
		icmp_hdr->un.echo.sequence);	
}

/*
Check if an arp request has been received.
Return: 1 if true
		0 if false
*/
int check_arp_req(struct arp_header *arp_hdr) {
	if (arp_hdr == NULL) {
		return 0;
	}
	int dest_interface = dest_reached(arp_hdr->tpa);
	if (dest_interface != -1) {
		if (arp_hdr->op == htons(ARPOP_REQUEST)) {
			return 1;
		}
	}
	return 0;
}

/*
Send arp reply.
Param: arp_hdr, pointer to the arp header of the packet.
	m_interface, the interface where the package was received from.	
*/
void send_arp_reply(struct arp_header *arp_hdr,
					int m_interface) {
	struct ether_header *eth_hdr_replied = 
					malloc(sizeof(struct ether_header));
	DIE(eth_hdr_replied == NULL, "memory");
	memcpy(eth_hdr_replied->ether_dhost,
				arp_hdr->sha, ETH_ALEN);
	uint8_t rinterface_mac[6];
	int dest_interface = dest_reached(arp_hdr->tpa);
	get_interface_mac(dest_interface, rinterface_mac);
	memcpy(eth_hdr_replied->ether_shost, rinterface_mac,
				ETH_ALEN);
	eth_hdr_replied->ether_type = htons(ETHERTYPE_ARP);

	send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr_replied,
				m_interface, htons(ARPOP_REPLY));
}

/*
Given an ip, check if the correspondent mac is known.
*/
int check_mac_known(uint32_t ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return 1;
		}
	}
	return 0;
}


/*
Send arp request.
Param: best_route, entry in rtable.
*/
void send_arp_req(struct route_table_entry *best_route) {
	struct ether_header *eth_hdr_req = malloc(sizeof(struct ether_header));
	DIE(eth_hdr_req == NULL, "memory");
	uint8_t d_mac[6];
	hwaddr_aton("ff:ff:ff:ff:ff:ff", d_mac);
	memcpy(eth_hdr_req->ether_dhost, d_mac, ETH_ALEN);

	uint8_t s_mac[6];
	get_interface_mac(best_route->interface, s_mac);

	memcpy(eth_hdr_req->ether_shost, s_mac, ETH_ALEN);
	eth_hdr_req->ether_type = htons(ETHERTYPE_ARP);


	send_arp(best_route->next_hop,
	inet_addr(get_interface_ip(best_route->interface)),
	eth_hdr_req, best_route->interface, htons(ARPOP_REQUEST));
}

/*
Check if an arp reply has been received.
Return: 1 if true
		0 if false
*/
int check_arp_reply(struct arp_header *arp_hdr) {
	if (arp_hdr == NULL) {
		return 0;
	}
	if (arp_hdr->op == htons(ARPOP_REPLY)) {
		return 1;
	}
	return 0;
}

/*
Update the arp table, adding a new entry containing the given ip and mac.
*/
void update_arp_table(uint32_t ip, uint8_t *mac) {
	arp_table[arp_table_len].ip = ip;
	memcpy(arp_table[arp_table_len].mac, mac, ETH_ALEN);
	arp_table_len++;
}


/*
Given a queue and an ip, send all packets in the queue that have that ip.
*/
void send_queue_packets(queue q, uint32_t d_ip) {
	packet *m;
	queue aux;
	aux = queue_create();

	while (!queue_empty(q)) {
		m = queue_deq(q);
		struct ether_header *eth_hdr = (struct ether_header *)m->payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m->payload + 
			                                sizeof(struct ether_header));
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		if (best_route->next_hop == d_ip) {
			// Complete Ethernet Header
			complete_ethhdr(eth_hdr, best_route);
			// Update TTL and recalculate the checksum
			ip_hdr->ttl--;
			recalculate_checksum(ip_hdr);
			// Send packet
			send_packet(best_route->interface, m);
		} else {
			queue_enq(aux, m);
		}
	}

	while(!queue_empty(aux)) {
		m = (packet *)queue_deq(aux);
		queue_enq(q, m);
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);
	// rtable memory allocation
	rtable = malloc(sizeof(struct route_table_entry) * RTABLE_LINES);
	DIE(rtable == NULL, "memory");
	rtable_size = read_rtable(rtable, argv[1]);
	// arp_table memory allocation
	arp_table = malloc(sizeof(struct arp_entry) * ARP_TABLE_LINES);
	// packets q
	queue q;
	q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + 
			                                sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = parse_icmp(m.payload);
		struct arp_header *arp_hdr = parse_arp(m.payload);
		struct route_table_entry *best_route;

		// Check if arp request
		if (check_arp_req(arp_hdr) == 1) {
			send_arp_reply(arp_hdr, m.interface);
			continue;
		}

		// Check if arp reply
		if (check_arp_reply(arp_hdr) == 1) {
			update_arp_table(arp_hdr->spa, arp_hdr->sha);
			send_queue_packets(q, arp_hdr->spa);
			continue;
		}

		// Check if echo request
		if (check_echo_req(ip_hdr ,icmp_hdr) == 1) {
			send_icmp_reply(eth_hdr, ip_hdr, icmp_hdr, m.interface);
			continue;
		}
	
		// Check the checksum
		if (validate_checksum(ip_hdr) == 0) {
			continue;
		}

		// Check TTL
		if (check_ttl(ip_hdr) == -1) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
			eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL,
			m.interface);
			continue;
		}

		// Find best matching route
		best_route = get_best_route(ip_hdr->daddr);
		if (best_route == NULL) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
			eth_hdr->ether_shost, ICMP_DEST_UNREACH, ICMP_NET_UNREACH,
			m.interface);
			continue;
		}

		// If unknown mac, send arp request
		if (check_mac_known(best_route->next_hop) == 0) {
			send_arp_req(best_route);
			// If arp request sent, add the packet in a queue 
			packet *queue_packet = malloc(sizeof(packet));
			*queue_packet = m;
			queue_enq(q, queue_packet);
			continue;
		}

		// Complete Ethernet Header
		complete_ethhdr(eth_hdr, best_route);

		// Update TTL and recalculate the checksum
		ip_hdr->ttl--;
		recalculate_checksum(ip_hdr);

		// Send packet
		send_packet(best_route->interface, &m);
	}
}
