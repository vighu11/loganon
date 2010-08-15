/*
 *	Data structures used by Loganon
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_STRUCTS_H
#define LOGANON_STRUCTS_H

#define IP_ADDR_LEN 15

/**
 * \brief IPs list for anonymization
 */
struct ip_anon {

	char ip_original[IP_ADDR_LEN+1];
	char ip_anonymized[IP_ADDR_LEN+1];

	struct ip_anon *next_ip;
};

#endif
