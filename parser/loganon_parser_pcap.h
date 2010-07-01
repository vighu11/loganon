/*
 *	Prototypes for loganon_parser_pcap
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_PARSER_PCAP_H
#define LOGANON_PARSER_PCAP_H

#include "loganon_errors.h"
#include "loganon_structs.h"

/*
 * Open pcap file in offline mode
 * @return ANON_FAIL if file doesn't exist, otherwise ANON_FAIL
 */
int8_t anonPcapOpen(const char *filename);

/*
 * Parse pcap file to find out sensitive data
 * @return 
 */
int8_t anonPcapSearchSensitiveData(struct ip_anon* ips);

void anonPcapFree(struct ip_anon *ips);

#endif
