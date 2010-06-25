/*
 *	Macros for packets parsing
 *	Authors: Guillaume TOURON
 */

#ifndef PROTO_UTILS_H
#define PROTO_UTILS_H

/*
 * Retrieve EtherType field from ethernet datagrams
 */
#define GET_ETHERTYPE(pkt) \
	((uint16_t)(pkt[12]) << 8) | (uint16_t)pkt

/* EtherType values */
#define ETHER_TYPE_IP	 0x0800
#define ETHER_TYPE_8021Q 0x8100

#endif
