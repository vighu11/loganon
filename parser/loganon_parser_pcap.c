/*
 *	Functions for pcap file parsing
 *	Authors: Guillaume TOURON
 */

#include <pcap.h>
#include <inttypes.h>

#include "debug_utils.h"
#include "proto_utils.h"

#include "loganon_queue.h"
#include "loganon_errors.h"


/* Pcap file handle */
static pcap_t *handle; 


static void displayIPsFound(struct ip_anon *ips)
{
	struct ip_anon* current = ips;

	/* Display each entry */
	for(; current; current = current->next_ip)
		print_debug(DBG_MED_LVL, "IP: %s\n", current->ip_original);
}

/*
 * Open pcap file in offline mode
 * @return ANON_FAIL if file doesn't exist, otherwise ANON_FAIL
 */
int8_t anonPcapOpen(const char *filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Open pcap file */
	handle = pcap_open_offline(filename, errbuf); 
	if(!handle) { 
		print_debug(DBG_HIG_LVL, "pcap_open_offline error: %s\n", errbuf); 
		return ANON_FAIL; 
	}
	
	return ANON_SUCCESS;
}

/*
 * Parse pcap file to find out sensitive data
 * @return 
 */
int8_t anonPcapSearchSensitiveData(struct ip_anon** ips)
{
	struct pcap_pkthdr header;
	/* Buffer for packets */
	u_char *packet;

   	while((packet = pcap_next(handle, &header))) { 

		u_char *pkt_ptr = (u_char *)packet;

      		/* Retrieve EtherType from ethernet packet */
 		uint16_t ether_type = GET_ETHERTYPE(pkt_ptr);

		struct in_addr *ip_addr = NULL;
		/* Compute offset of IP datagram */
		if(ether_type == ETHER_TYPE_IP) {
			ip_addr = GET_IPSRC(pkt_ptr, 14);
		}
     		else if(ether_type == ETHER_TYPE_8021Q) {
			ip_addr = GET_IPSRC(pkt_ptr, 18);
		}

		/* Add new IP into the list if necessary */
		insertNewIP(inet_ntoa(*ip_addr), ips);
 	}

	/* Display all entries (for debug) */
	displayIPsFound(*ips);

	return ANON_SUCCESS;
}
