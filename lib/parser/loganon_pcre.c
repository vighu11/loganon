/*
 *	Functions for regular expressions (pcre wrapper)
 *	Authors: Guillaume TOURON
 */

#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug_utils.h"

#include "loganon_queue.h"
#include "loganon_regex.h"


/*
 * Retrieve IPs from buffer
 * @param ips IPs linked list
 * @param buffer buffer we wants search IPs into
 * @return ANON_FAIL if pcre fails, otherwise ANON_SUCCESS
 */
extern
int8_t pcre_search_ip(struct ip_anon **ips, const char *buffer)
{
	pcre *regex;

	/* PCRE error buffer */
	const char *errbuf;
	/* For results */
	int32_t matches, ovector[OVECCOUNT];

	/* Compile IPs-regex */
	regex = pcre_compile(IP_REGEX, 0, &errbuf, NULL, NULL);
	if(!regex) {

		print_debug(DBG_HIG_LVL, "pcre_compile error: %s\n", errbuf);
		return ANON_FAIL;
	}

	/* Apply compiled IPs-regex */
	matches = pcre_exec(regex, NULL, buffer, strlen(buffer), 0, 0,
					ovector, OVECCOUNT);
	
	/* Check results */
	

	return ANON_SUCCESS;
}
