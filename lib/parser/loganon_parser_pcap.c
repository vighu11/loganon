/*
 *	Functions for pcap file parsing
 *	Authors: Guillaume TOURON
 */

#include <pcap.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "debug_utils.h"
#include "proto_utils.h"

#include "loganon_queue.h"
#include "loganon_errors.h"


/* Pcap file handle for reading */
static pcap_t *handleR = NULL; 

/* Pcap file handle for writing */
static pcap_dumper_t *handleW;

/* Number of processed packets */
static uint32_t numPackets;

/*
 * Pcap files names
 */
static char *g_filenameIn, *g_filenameOut;

/*
 * Data sent to PCAP parser's callback
 */
struct CBParam {

	pcap_dumper_t *savefile;
	/* Anonymized data */
	struct ip_anon *ip_list;
};

/*
 * Display each IP found
 * @param ips pointer on the IPs list
 */
static
void display_ip_addr(struct ip_anon *ips)
{
	struct ip_anon* current = ips;

	/* Display each entry */
	for(; current; current = current->next_ip)
		print_debug(DBG_MED_LVL, "IP: %s\n", current->ip_original);
}

/*
 * Open a pcap file in offline mode
 * This function will be used several times
 * @param filename name of file to open
 */
static 
int8_t open_pcap_file(const char *filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	handleR = pcap_open_offline(filename, errbuf); 
	if(!handleR) { 
		print_debug(DBG_HIG_LVL, "pcap_open_offline error: %s\n", errbuf);
		/* Return failure */
		return ANON_FAIL; 
	}

	return ANON_SUCCESS;
}

/*
 * Compute IP checksum
 * @param packet packet to compute checksum
 * @return IP checksum in host format
 */
static inline
uint16_t compute_ip_checksum(const u_char *packet)
{
	struct ip *ip_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	uint32_t sum = 0;

	uint8_t i = 0;
	for(; i < (ip_header->ip_hl*2); i++)
		/* Sum all 16-bits words */
		sum += GET_16_WORD(ip_header, i);

	/* Substract checksum field */
	sum -= ip_header->ip_sum;

	/* Add carries */
	while(sum >> 16) 
		sum = (sum >> 16) + (sum & 0xFFFF);

	/* Print checksum in network format */
	print_debug(DBG_MED_LVL, "IP Checksum: 0x%.4X\n",
						htons((uint16_t)~sum));

	return ~sum;
}

/*
 * Update IP checksum after anonymization
 * @param packet packet to update checksum
 */
static inline
void update_ip_checksum(u_char *packet)
{
	struct ip *ip_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	/* Update with new checksum */
	ip_header->ip_sum = compute_ip_checksum(packet);
}

/*
 * Compute UDP checksum
 * @param packet packet to compute checksum
 * @return UDP checksum in host format
 */
static inline 
uint16_t compute_udp_checksum(const u_char *packet)
{
	struct ip *ip_header = NULL;
	/* UDP header infos */
	struct udphdr *udp_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	/* Retrieve UDP header */
	GET_UDP_HEADER(ip_header, udp_header);

	/* Compute padding */
	uint8_t padding = ntohs(udp_header->len) % 2, i;

	uint32_t sum = 0;

	for(i = 0; i < ntohs(udp_header->len)/2; i++)
		/* Sum all 16-bits words */
		sum += GET_16_WORD(udp_header, i);

	/* Substract checksum field */
	sum -= udp_header->check;

	if(padding)
		sum += ntohs(GET_8_WORD(udp_header, i*2) << 8);
	
	/* Add pseudo header */
	for(i = 0; i < 4; i++)
		sum += GET_16_WORD(&ip_header->ip_src, i);

	sum += htons((uint16_t)ip_header->ip_p) + (udp_header->len);

	/* Add carries */
	while(sum >> 16) 
		sum = (sum >> 16) + (sum & 0xFFFF);

	/* Debug purpose */
	print_debug(DBG_MED_LVL, "Checksum: 0x%.4X\n",
							htons((uint16_t)~sum));

	return (uint16_t)~sum;
}

/*
 * Update UDP checksum after anonymization
 * @param packet packet to update checksum
 */
static inline
void update_udp_checksum(u_char *packet)
{
	struct ip *ip_header = NULL;
	/* UDP header infos */
	struct udphdr *udp_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	/* Retrieve UDP header */
	GET_UDP_HEADER(ip_header, udp_header);

	/* Update with new checksum */
	udp_header->check = compute_udp_checksum(packet);
}

/*
 * Compute TCP checksum
 * @param packet packet to compute checksum
 * @return TCP checksum in host format
 */
static inline
uint16_t compute_tcp_checksum(const u_char *packet)
{
	struct ip *ip_header = NULL;
	/* TCP header infos */
	struct tcphdr *tcp_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	/* Retrieve TCP header */
	GET_TCP_HEADER(ip_header, tcp_header);

	uint32_t sum = 0;

	/* Compute length (TCP Header + Payload) */
	uint32_t len = ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2);

	/* Compute padding */
	uint8_t padding = len % 2;

	uint32_t i;
	for(i = 0; i < len/2; i++)
		/* Sum all 16-bits words */
		sum += GET_16_WORD(tcp_header, i);

	/* Substract checksum field */
	sum -= tcp_header->check;

	if(padding)
		sum += ntohs(GET_8_WORD(tcp_header, i*2) << 8);
	
	/* Add pseudo header */
	for(i = 0; i < 4; i++)
		sum += GET_16_WORD(&ip_header->ip_src, i);

	sum += htons((uint16_t)ip_header->ip_p) + (len << 8);

	/* Add carries */
	while(sum >> 16) 
		sum = (sum >> 16) + (sum & 0xFFFF);

	/* Debug purpose */
	print_debug(DBG_MED_LVL, "Checksum: 0x%.4X\n",
							htons((uint16_t)~sum));

	return (uint16_t)~sum;	
}

/*
 * Update TCP checksum after anonymization
 * @param packet packet to update checksum
 */
static inline
void update_tcp_checksum(u_char *packet)
{
	struct ip *ip_header = NULL;
	/* UDP header infos */
	struct tcphdr *tcp_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	/* Retrieve UDP header */
	GET_TCP_HEADER(ip_header, tcp_header);

	/* Update with new checksum */
	tcp_header->check = compute_tcp_checksum(packet);
}

/*
 * Check if packet has an IP header
 * @param packet packet we check it has a IP header
 * @return 1 if packet has an IP header
 */
static inline
uint8_t contain_ip_header(u_char *packet)
{
	/* Retrieve EtherType from ethernet packet */
	uint16_t ether_type = GET_ETHERTYPE(packet);

	return (ether_type == ETHER_TYPE_IP) || (ether_type == ETHER_TYPE_8021Q);
}

/*
 * Check if packet has an UDP header
 * @param packet packet we check it has a UDP header
 * @return 1 if packet has an UDP header
 */
static inline
uint8_t contain_udp_header(u_char *packet)
{
	struct ip *ip_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	/* Check is an UDP header is encapsulated */
	return (ip_header->ip_p == IPPROTO_UDP);
}

/*
 * Check if packet has a TCP header
 * @param packet packet we check it has a TCP header
 * @return 1 if packet has an TCP header
 */
static inline
uint8_t contain_tcp_header(u_char *packet)
{
	struct ip *ip_header = NULL;

	/* Retrieve IP header */
	GET_IP_HEADER(packet, ip_header);

	/* Check is an TCP header is encapsulated */
	return (ip_header->ip_p == IPPROTO_TCP);
}

/*
 * Reads IP addresses in IP packet header
 * @param ipsrc store read IP src (NULL if doesn't exist)
 * @param ipdst store read IP dst (NULL if doesn't exist)
 * @param packet packet to parse
 */
static inline
void read_ip_addr(struct in_addr **ipsrc, struct in_addr **ipdst,
								const u_char *packet)
{
	*ipdst = NULL;
	*ipsrc = NULL;

     	/* Retrieve EtherType from ethernet packet */
	uint16_t ether_type = GET_ETHERTYPE(packet);

	/* Compute offset of IP datagram */
	if(ether_type == ETHER_TYPE_IP) {

		*ipsrc = GET_IPSRC(packet, 14);
		*ipdst = GET_IPDST(packet, 14);
	}
	/* VLAN tagged frame */
     	else if(ether_type == ETHER_TYPE_8021Q) {

		*ipsrc = GET_IPSRC(packet, 18);
		*ipdst = GET_IPDST(packet, 18);
	}
}

/*
 * Open pcap file in offline mode
 * @param filenameIn name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist, otherwise ANON_SUCCESS
 */
extern
int8_t anon_pcap_open(const char *filenameIn, const char *filenameOut)
{
	/* Open pcap file for parsing */
	int8_t ret = open_pcap_file(filenameIn);
	if(ret == ANON_FAIL)
		return ret;

	/* Allocate memory for filenameIn */
	g_filenameIn = malloc(strlen(filenameIn) + 1);

	assert(g_filenameIn != NULL);

	/* Allocate memory for filenameOut */
	g_filenameOut = malloc(strlen(filenameOut) + 1);

	assert(g_filenameOut != NULL);

	/* Copy files names */
	strncpy(g_filenameIn, filenameIn, strlen(filenameIn) + 1);
	strncpy(g_filenameOut, filenameOut, strlen(filenameOut) + 1);

	return ANON_SUCCESS;
}

/*
 * Parse pcap file to find out sensitive data
 * @param ips pointer on a pointer on the IPs list
 * @return ANON_FAIL if search fails, otherwise ANON_SUCCESS
 */
extern
int8_t anon_pcap_search_data(struct ip_anon **ips)
{
	struct pcap_pkthdr header;

	/* Buffer for packets */
	const u_char *packet;

   	while((packet = pcap_next(handleR, &header))) {

		struct in_addr *ip_addr_src, *ip_addr_dst;

		/* Retrieve addresses from packet if exist */
		read_ip_addr(&ip_addr_src, &ip_addr_dst, packet);

		/* Add new IP into the list if necessary */
		if(ip_addr_src && ip_addr_dst) {

			insert_new_ip(inet_ntoa(*ip_addr_src), ips);
			insert_new_ip(inet_ntoa(*ip_addr_dst), ips);
		}
	}

	/* Display all entries for debug */
	display_ip_addr(*ips);

	/* Close handle */
	pcap_close(handleR);

	return ANON_SUCCESS;
}

/*
 * Perform anonymization on sensitive data previously retrieved
 */
static 
void read_callback(u_char *user, struct pcap_pkthdr *phdr,
								u_char *pdata)
{
	print_debug(DBG_MED_LVL, "Processing packet %u\n", numPackets);

	/* Get user structure */
	struct CBParam *param = (struct CBParam *)user;

	if(contain_ip_header(pdata)) {

		/*
		 * For IP anonymization
		 */
		struct in_addr *ip_addr_src, *ip_addr_dst;

		/* Retrieve IP addresses */
		read_ip_addr(&ip_addr_src, &ip_addr_dst, pdata);

		/*
		 * Apply anonymized data from linked lists
		 */
		struct ip_anon *ips = param->ip_list;

		/* Compute actual IP checksum */
		uint16_t ip_checksum = compute_ip_checksum(pdata);

		/* We necessary have an ip_list */
		assert(ips != NULL);

		/* Search ip addresses in dictionnary */
		ip_addr_src->s_addr = get_anonymized_ip(
					ADDR_LONG_TO_STR(ip_addr_src->s_addr), ips);

		ip_addr_dst->s_addr = get_anonymized_ip(
					ADDR_LONG_TO_STR(ip_addr_dst->s_addr), ips);

		update_ip_checksum(pdata);

		if(contain_udp_header(pdata)) {

			/* Compute actual UDP checksum if exists */
			uint16_t udp_checksum = compute_udp_checksum(pdata);

			update_udp_checksum(pdata);
		}
		else if(contain_tcp_header(pdata)) {

			/* Compute actual TCP checksum */
			uint16_t tcp_checksum = compute_tcp_checksum(pdata);

			update_tcp_checksum(pdata);
		}
	}
	
	/* Dump new packet (anonymized) */
	pcap_dump((u_char *)param->savefile, phdr, pdata);

	numPackets++;
}

/*
 * Write anonymized sensitive data into a new file (filenameOut)
 * @param ips pointer on the anonymized IPs list
 * @return ANON_FAIL if can't write file, otherwise ANON_SUCCESS
 */
extern
int8_t anon_pcap_write_data(struct ip_anon *ips)
{
	/* Open pcap file for reading */
	int8_t ret = open_pcap_file(g_filenameIn);
	if(ret == ANON_FAIL)
		return ret;

	/* Open pcap file for writing */
	handleW = pcap_dump_open(handleR, g_filenameOut);
	if(!handleW) {

		print_debug(DBG_HIG_LVL, "pcap_dump_open error: %s\n",
					pcap_geterr(handleR));

		/* Free handle previously opened */
		pcap_close(handleR);

		return ANON_FAIL;
	}

	/* User param for callback */
	struct CBParam cbParam = {handleW, ips};

	/* Process each packet */
	ret = pcap_dispatch(handleR, 0, (pcap_handler)read_callback,
							(u_char *)&cbParam);
	if(ret == -1) {

		print_debug(DBG_HIG_LVL, "pcap_dispatch error: %s\n",
					pcap_geterr(handleR));

		/* Free opened handles */
		pcap_close(handleR);
		pcap_dump_close(handleW);

		return ANON_FAIL;
	}

	return ANON_SUCCESS;
}

/*
 * Free all allocated memory
 * @param ips pointer on the IPs list
 */
extern
void anon_pcap_free(struct ip_anon *ips)
{
	/* Close handles */
	if(handleR)
		pcap_close(handleR);

	if(handleW)
		pcap_dump_close(handleW);

	/* Free memory for files names */
	free(g_filenameOut);
	free(g_filenameIn);

	/* Free list */
	free_list_ips(ips);
}
