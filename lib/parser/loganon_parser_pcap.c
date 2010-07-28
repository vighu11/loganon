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
static pcap_dumper_t *handleW = NULL;

/*
 * Pcap files names
 */
static char *g_filenameIn, *g_filenameOut;

/*
 * Data sent to pcap parser's callback
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

	GET_IP_HEADER(packet, ip_header);

	/* Array for all 16-bits words in IP header */
	uint16_t *words = malloc(sizeof(uint16_t)*(ip_header->ip_hl*2));
	assert(words != NULL);

	uint8_t i = 0;
	for(; i < (ip_header->ip_hl*2); i++)
		words[i] = *((uint16_t *)ip_header + i);

	/* Erase checksum field */
	words[5] = 0;

	/* Compute checksum */
	uint32_t sum1 = 0;
	uint16_t sum2 = 0;

	/* Sum all 16-bits words */
	for(i = 0; i < (ip_header->ip_hl*2); i++)
		sum1 += words[i];

	if(sum1 > 0xFFFF)
		sum2 = (sum1 >> 16) + (sum1 & 0xFFFF);
	else
		sum2 = (uint16_t)sum1;

	/* Debug purpose */
	print_debug(DBG_LOW_LVL, "IP Checksum: 0x%.4X\n",
						htons((~sum2 & 0xFFFF)));

	free(words);

	return ~sum2;
}

/*
 * Update IP checksum after anonymization
 * @param packet packet to update checksum
 */
static inline
void update_ip_checksum(u_char *packet)
{
	u_char *pkt_ptr = (u_char *)packet;

	struct ip *ip_header = NULL;

	GET_IP_HEADER(packet, ip_header);

	/* Update with new checksum */
	ip_header->ip_sum = compute_ip_checksum(packet);
}

/*
 * Reads IP addresses in IP packet header
 * @param ipsrc store readen IP src (NULL if doesn't exist)
 * @param ipdst store readen IP dst (NULL if doesn't exist)
 * @param packet packet to parse
 */
static inline
void read_ip_addr(struct in_addr **ipsrc, struct in_addr **ipdst,
								const u_char *packet)
{
	u_char *pkt_ptr = (u_char *)packet;

	*ipdst = NULL;
	*ipsrc = NULL;

     	/* Retrieve EtherType from ethernet packet */
	uint16_t ether_type = GET_ETHERTYPE(pkt_ptr);

	/* Compute offset of IP datagram */
	if(ether_type == ETHER_TYPE_IP) {

		*ipsrc = GET_IPSRC(pkt_ptr, 14);
		*ipdst = GET_IPDST(pkt_ptr, 14);
	}
	/* VLAN tagged frame */
     	else if(ether_type == ETHER_TYPE_8021Q) {

		*ipsrc = GET_IPSRC(pkt_ptr, 18);
		*ipdst = GET_IPDST(pkt_ptr, 18);
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

			insertNewIP(inet_ntoa(*ip_addr_src), ips);
			insertNewIP(inet_ntoa(*ip_addr_dst), ips);
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
	print_debug(DBG_LOW_LVL, "New packet processed!\n");

	/* Get user structure */
	struct CBParam *param = (struct CBParam *)user;

	/*
	 * For IP anonymization
	 */
	struct in_addr *ip_addr_src, *ip_addr_dst;

	/* Retrieve IP addresses */
	read_ip_addr(&ip_addr_src, &ip_addr_dst, pdata);

	/*
	 * Apply anonymized data from linked lists
	 */
	if(ip_addr_src && ip_addr_dst) {

		struct ip_anon *ips = param->ip_list;

		/* Compute actual IP checksum */
		uint16_t ip_checksum = compute_ip_checksum(pdata);

		/* TODO: Check if checksum is corrupted */

		/* We have necessary an ip_list */
		assert(ips != NULL);

		/* Search ip addresses in dictionnary */
		ip_addr_src->s_addr = getAnonymizedIP(
					ADDR_LONG_TO_STR(ip_addr_src->s_addr), ips);

		ip_addr_dst->s_addr = getAnonymizedIP(
					ADDR_LONG_TO_STR(ip_addr_dst->s_addr), ips);

		update_ip_checksum(pdata);
	}
	
	/* Dump new packet (anonymized) */
	pcap_dump((u_char *)param->savefile, phdr, pdata);
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
	freeListIPs(ips);
}
