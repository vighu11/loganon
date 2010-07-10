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
 * @param filenameIn name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist, otherwise ANON_SUCCESS
 */
extern
int8_t anon_pcap_open(const char *filenameIn, const char *filenameOut);

/*
 * Parse pcap file to find out sensitive data
 * @param ips pointer on a pointer on the IPs list
 * @return ANON_FAIL if search fails, otherwise ANON_SUCCES
 */
extern
int8_t anon_pcap_search_data(struct ip_anon **ips);

/*
 * Write anonymized sensitive data into a new file (filenameOut)
 * @param ips pointer on the anonymized IPs list
 * @return ANON_FAIL if can't write file, otherwise ANON_SUCCESS
 */
extern
int8_t anon_pcap_write_data(struct ip_anon *ips);

/*
 * Free all allocated memory
 * @param ips pointer on the IPs list
 */
extern
void anon_pcap_free(struct ip_anon *ips);

#endif
