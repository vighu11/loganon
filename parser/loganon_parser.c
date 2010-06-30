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


/* IP adresses to anonymize */
static struct ip_anon *ip_list;

/*
 * Open file for anonymization
 * @return ANON_FAIL if file doesn't exist or is unsupported
 */
int8_t initLoganon(const char *filename)
{
	int8_t ret;

	if(strstr(filename, PCAP_FILE)) {

		/* We parse a pcap file */
		ret = anonPcapOpen(filename);
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
