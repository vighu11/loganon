/*
 *	Functions for logs anonymization
 *	Authors: Guillaume TOURON
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "debug_utils.h"
#include "files_extensions.h"
#include "loganon_parser_pcap.h"

/*
 * File type enum
 */
typedef enum {UNKNOWN, PCAP, SYSLOG} FILETYPE;

/* Type of file being processed */
FILETYPE FileType = UNKNOWN;


/* IP addresses to anonymize */
static struct ip_anon *ip_list;

/*
 * Open file for anonymization
 * @param filename name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist or is unsupported
 */
int8_t initLoganon(const char *filenameIn, const char *filenameOut)
{
	int8_t ret;

	if(strstr(filenameIn, PCAP_FILE)) {

		FileType = PCAP;

		/* We parse a pcap file */
		ret = anonPcapOpen(filenameIn, filenameOut);
		if(ret == ANON_FAIL) {

			print_debug(DBG_HIG_LVL, "anonPcapOpen error\n");
			return ret;
		}

		/* Search for sensitive data */
		ret = anonPcapSearchSensitiveData(&ip_list);
		if(ret == ANON_FAIL) {

			print_debug(DBG_HIG_LVL, "anonPcapSearchSensitiveData error\n");
			return ret;
		}
	}

	return ANON_SUCCESS;
}

/*
 * Apply anonymization on sensitive data
 * @param level level of anonymization
 */
int8_t loganonAnonymize(uint8_t level)
{
	/* TODO: Use EscoVa's functions */

	/* Write pcap file with anonymized data */
	anonPcapWriteAnonymizedData(ip_list);

	return ANON_SUCCESS;
}

/*
 * Close handles and free memory
 * @return ANON_FAIL if no file has been successfully opened
 */
int8_t terminateLoganon()
{
	switch(FileType) {

		case UNKNOWN:
			return ANON_FAIL;

		case PCAP:
			/* Pcap file */
			anonPcapFree(ip_list);
			break;

		default:
			/* Should nvere happen */
			print_debug(DBG_HIG_LVL, "Internal error: %s %u\n",
									__FILE__, __LINE__);

			return ANON_FAIL;
	}

	return ANON_SUCCESS;
}
