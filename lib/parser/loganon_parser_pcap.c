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
static inline void debugDisplayIPsFound(struct ip_anon *ips)
{
	struct ip_anon* current = ips;

	/* Display each entry */
	for(; current; current = current->next_ip)
		print_debug(DBG_MED_LVL, "IP: %s\n", current->ip_original);
}

/*
 * Open a pcap file in offline mode
 * ! This function will be used several times !
 * @param filename name of file to open
 */
static inline int8_t openPcapFile(const char *filename)
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

static inline void getIPAddresses(struct in_addr **ipsrc, struct in_addr **ipdst,
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
int8_t anonPcapOpen(const char *filenameIn, const char *filenameOut)
{
	/* Open pcap file for parsing */
	int8_t ret = openPcapFile(filenameIn);
	if(ret == ANON_FAIL) {

		return ret;
	}

	/* Allocate memory for filenameIn*/
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
int8_t anonPcapSearchSensitiveData(struct ip_anon **ips)
{
	struct pcap_pkthdr header;

	/* Buffer for packets */
	const u_char *packet;

   	while((packet = pcap_next(handleR, &header))) {

		struct in_addr *ip_addr_src, *ip_addr_dst;

		/* Retrieve addresses from packet */
		getIPAddresses(&ip_addr_src, &ip_addr_dst, packet);

		/* Add new IP into the list if necessary */
		insertNewIP(inet_ntoa(*ip_addr_src), ips);
		insertNewIP(inet_ntoa(*ip_addr_dst), ips);
	}

	/* Display all entries for debug */
	debugDisplayIPsFound(*ips);

	/* Close handle */
	pcap_close(handleR);

	return ANON_SUCCESS;
}

/*
 * Perform anonymization on sensitive data previously retrieved
 */
static void anonPcapCallback(u_char *user, struct pcap_pkthdr *phdr, 
						u_char *pdata)
{
	print_debug(DBG_LOW_LVL, "New packet processed!\n");

	/* Get user structure */
	struct CBParam *param = (struct CBParam *)user;

	struct in_addr *ip_addr_src, *ip_addr_dst;

	/* Retrieve IP addresses */
	getIPAddresses(&ip_addr_src, &ip_addr_dst, pdata);

	/* TODO:
	 * Apply anonymized data from linked lists
	 */
	ip_addr_src->s_addr = inet_addr("1.2.3.4");
	ip_addr_dst->s_addr = inet_addr("5.6.7.8");
	
	/* Dump new packet (anonymized) */
	pcap_dump((u_char *)param->savefile, phdr, pdata);
}

/*
 * Write anonymized sensitive data into a new file (filenameOut)
 * @param ips pointer on the anonymized IPs list
 * @return ANON_FAIL if can't write file, otherwise ANON_SUCCESS
 */
int8_t anonPcapWriteAnonymizedData(struct ip_anon *ips)
{
	/* Open pcap file for reading */
	int8_t ret = openPcapFile(g_filenameIn);
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
	ret = pcap_dispatch(handleR, 0, (pcap_handler)anonPcapCallback,
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
void anonPcapFree(struct ip_anon *ips)
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
