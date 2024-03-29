/*
 *	Macros for packets parsing and conversions
 *	Authors: Guillaume TOURON
 */

#ifndef PROTO_UTILS_H
#define PROTO_UTILS_H

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>


/**
 * \brief Retrieve IP header from packet
 */
#define GET_IP_HEADER(pkt, ip_hdr)			\
								\
	uint16_t ether_type = GET_ETHERTYPE(pkt);	\
								\
	if(ether_type == ETHER_TYPE_IP)		\
		ip_hdr = (struct ip *)(pkt + 14);	\
								\
     	else if(ether_type == ETHER_TYPE_8021Q)	\
		ip_hdr = (struct ip *)(pkt + 18);	\
	else							\
		assert(0);

/**
 * \brief Retrieve UDP header from IP header
 */
#define GET_UDP_HEADER(ip_hdr, udp_hdr)							\
													\
	if(ip_hdr->ip_p == IPPROTO_UDP) 							\
		udp_hdr = (struct udphdr *)((uint32_t *)ip_hdr+ip_header->ip_hl);	\
	else												\
		assert(0);

/**
 * \brief Retrieve TCP header from IP header
 */
#define GET_TCP_HEADER(ip_hdr, tcp_hdr)							\
													\
	if(ip_hdr->ip_p == IPPROTO_TCP) 							\
		tcp_hdr = (struct tcphdr *)((uint32_t *)ip_hdr+ip_header->ip_hl);	\
	else												\
		assert(0);


/**
 * \brief Retrieve EtherType field from ethernet datagrams
 */
#define GET_ETHERTYPE(pkt) 					\
				 					\
	((uint16_t)(pkt[12]) << 8) | (uint16_t)pkt[13]

/**
 * \brief Retrieve IP_src field from IP datagram
 * off is computed according to EtherType
 */
#define GET_IPSRC(pkt, off)		   	 \
				    		   	 \
	&(((struct ip*)(pkt+off))->ip_src)

/**
 * \brief Retrieve IP_dst field from IP datagram
 * off is computed according to EtherType
 */
#define GET_IPDST(pkt, off)			  \
				   			  \
	&(((struct ip*)(pkt+off+4))->ip_src)


/**
 * \brief Network conversion
 * from long to string
 */
#define ADDR_LONG_TO_STR(ip_addr)		     \
							     \
	inet_ntoa(*((struct in_addr *)&ip_addr))

/**
 * \brief Network conversion
 * from long to string
 */
#define ADDR_STR_TO_LONG(ip_addr) \
					    \
	inet_addr(ip_addr)


/**
 * \brief Get a 16-bits word
 */
#define GET_16_WORD(buff, off)  \
					  \
	*((uint16_t *)buff + off)

/**
 * \brief Get a 16-bits word
 */
#define GET_8_WORD(buff, off)  \
					 \
	*((uint8_t *)buff + off)


/**
 * \brief EtherType values
 */
#define ETHER_TYPE_IP	 0x0800
#define ETHER_TYPE_8021Q 0x8100

#endif
