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
	int32_t matches, erroffset, ovector[OVECCOUNT];

	/* Compile IPs-regex */
	regex = pcre_compile(IP_REGEX, 0, &errbuf, &erroffset, NULL);
	if(!regex) {

		print_debug(DBG_HIG_LVL, "pcre_compile error: %s\n", errbuf);
		return ANON_FAIL;
	}

	/* Apply compiled IPs-regex */
	matches = pcre_exec(regex, NULL, buffer, strlen(buffer),
					 0, 0, ovector, OVECCOUNT);
	
	/* Check results */
	if (matches < 0) {
		/* Free compiled regex */
		pcre_free(regex);

		switch (matches) {
			case PCRE_ERROR_NOMATCH: break;

			default:
				print_debug(DBG_HIG_LVL, 
						"pcre_exec error: %d\n", matches);
				/* An internal error occured */
				return ANON_FAIL;
		}

		return ANON_SUCCESS;
	}

	uint32_t i;
	for (i = 0; i < matches; i++) {
		/* For debug purpose */
		print_debug(DBG_LOW_LVL, "IP: %.*s\n",
				ovector[2*i+1] - ovector[2*i], 
					  buffer + ovector[2*i]);
	}

	pcre_free(regex);

	return ANON_SUCCESS;
}
