/*
 *	Data structures used by Loganon
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_STRUCTS_H
#define LOGANON_STRUCTS_H

/*
 * IPs list for anonymization
 */
struct ip_anon {

	char ip_original[16];
	char ip_anonymized[16];

	struct ip_anon *nextIp;
};

#endif
