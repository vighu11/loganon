/*
 *	Functions for logs anonymization
 *	Authors: Guillaume TOURON
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/* Anonymization functions */
#include "../include/loganon/ip_anon.h"

#include "files_extensions.h"

#include "debug_utils.h"
#include "proto_utils.h"

#include "loganon_errors.h"
#include "loganon_parser_pcap.h"
#include "loganon_parser_syslog.h"


/*
 * File type enumeration
 */
typedef enum {UNKNOWN, PCAP, SYSLOG} FILETYPE;

/* Type of file being processed */
static FILETYPE FileType = UNKNOWN;


/* IP addresses to anonymize */
static struct ip_anon *ip_list;

/*
 * Open file for anonymization
 * @param filename name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist or is unsupported
 */
extern
int8_t loganon_init(const char *filenameIn, const char *filenameOut)
{
	int8_t ret;

	if(strstr(filenameIn, PCAP_FILE)) {

		FileType = PCAP;

		/* We parse a PCAP file */
		ret = anon_pcap_open(filenameIn, filenameOut);
		ANON_PROCESS_ERROR("anon_pcap_open");

		/* Search for sensitive data */
		ret = anon_pcap_search_data(&ip_list);
		ANON_PROCESS_ERROR("anon_pcap_search_data");
	}
	else {

		FileType = SYSLOG;

		/* We parse SYSLOG */
		ret = anon_syslog_open(filenameIn, filenameOut);
		ANON_PROCESS_ERROR("anon_syslog_open");

		/* Sensitive data in SYSLOG */
		ret = anon_syslog_search_data(&ip_list);
		ANON_PROCESS_ERROR("anon_syslog_search_data");
	}

	return ANON_SUCCESS;
}

/*
 * Anonymize IPv4 addresses
 */
static
void anonymize_ipv4()
{
	/* Create a new hash table for ips_v4 */
	struct ip_node *hash_table = loganon_hash_table();

	/* For each IP, anonymize it ! */
	struct ip_anon *current = ip_list;
	for(; current; current = current->next_ip) {

		uint32_t old_ip = ADDR_STR_TO_LONG(current->ip_original);

		/* Anonymize original IP */
		uint32_t new_ip = loganon_ipv4_hash_anon(hash_table, old_ip);

		char *ip_anonymized = ADDR_LONG_TO_STR(new_ip);

		/* Save anonymized ip in the list */
		strncpy(current->ip_anonymized, ip_anonymized,
						 strlen(ip_anonymized) + 1);

		/* Debug purpose */
		print_debug(DBG_HIG_LVL, "%-15s -> %-15s\n", current->ip_original,
								 	  current->ip_anonymized);
	}

	/* Free memory */
	loganon_destruct_hash(hash_table);
}

/*
 * Apply anonymization on sensitive data
 * @param level level of anonymization
 * @return ANON_SUCCESS if anonymization succeeded, otherwise ANON_FAIL
 */
extern
int8_t loganon_anonymize(uint8_t level)
{
	/* Anonymization */
	anonymize_ipv4();

	/* Write pcap file with anonymized data */
	switch(FileType) {

		case PCAP:
			anon_pcap_write_data(ip_list);
			break;

		case SYSLOG:
			break;

		default:
			/* Should never happen */
			print_debug(DBG_HIG_LVL, "Internal error: %s %u\n",
									__FILE__, __LINE__);

			return ANON_FAIL;
	}

	return ANON_SUCCESS;
}

/*
 * Close handles and free memory
 * @return ANON_FAIL if no file has been successfully opened
 */
extern
int8_t loganon_terminate()
{
	switch(FileType) {

		case PCAP:
			/* Pcap file */
			anon_pcap_free(ip_list);
			break;

		case SYSLOG:
			/* SYSLOG file */
			anon_syslog_free(ip_list);
			break;

		default:
			/* Should never happen */
			print_debug(DBG_HIG_LVL, "Internal error: %s %u\n",
									__FILE__, __LINE__);

			return ANON_FAIL;
	}

	return ANON_SUCCESS;
}
