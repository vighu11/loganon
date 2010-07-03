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
 * @param filename name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist, otherwise ANON_FAIL
 */
int8_t anonPcapOpen(const char *filenameIn, const char *filenameOut);

/*
 * Parse pcap file to find out sensitive data
 * @param ips pointer on a pointer on the IPs list
 * @return ANON_FAIL if search fails, otherwise ANON_SUCCES
 */
int8_t anonPcapSearchSensitiveData(struct ip_anon **ips);

/*
 * Write anonymized sensitive data into a new file (filenameOut)
 * @param ips pointer on the anonymized IPs list
 */
int8_t anonPcapWriteAnonymizedData(struct ip_anon *ips);

/*
 * Free all allocated memory
 * @param ips pointer on the IPs list
 */
void anonPcapFree(struct ip_anon *ips);

#endif
