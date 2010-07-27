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
 * Matches a PCRE regex
 * @param tab results tab
 * @param nb number of results
 * @param buffer string on which we search
 * @param pattern regex PCRE we apply on buffer
 * @return ANON_FAIL if pcre fails, otherwise ANON_SUCCESS
 */
static
int8_t match_regex(int32_t *tab, int32_t *nb,
				const char *buffer, const char *pattern)
{
	pcre *regex;

	/* PCRE error buffer */
	const char *errbuf;
	/* For results */
	int32_t erroffset;

	/* Compile IPs-regex */
	regex = pcre_compile(pattern, 0, &errbuf, &erroffset, NULL);
	if(!regex) {

		print_debug(DBG_HIG_LVL, "pcre_compile error: %s\n", errbuf);
		return ANON_FAIL;
	}

	/* Apply compiled IPs-regex */
	*nb = pcre_exec(regex, NULL, buffer, strlen(buffer),
					 0, 0, tab, OVECCOUNT);
	
	/* Check results */
	if(*nb < 0) {
		/* Free compiled regex */
		pcre_free(regex);

		switch(*nb) {
			case PCRE_ERROR_NOMATCH: break;

			default:
				print_debug(DBG_HIG_LVL,
						"pcre_exec error: %d\n", *nb);
				/* An internal error occured */
				return ANON_FAIL;
		}

		return ANON_SUCCESS;
	}

	pcre_free(regex);

	return ANON_SUCCESS;
}

/*
 * Retrieve IPs from buffer
 * @param ips IPs linked list
 * @param buffer buffer we wants search IPs into
 * @return ANON_FAIL if pcre fails, otherwise ANON_SUCCESS
 */
extern
int8_t pcre_search_ip(struct ip_anon **ips, const char *buffer)
{
	/* Results tab */
	int32_t ovector[OVECCOUNT], matches;

	/* Found patterns */
	int8_t ret = match_regex(ovector, &matches, buffer, IP_REGEX);
	if(ret == ANON_FAIL)
		return ret;

	uint32_t len, i;
	for (i = 0; i < matches; i++) {

		len = ovector[2*i+1] - ovector[2*i];

		/* For debug purpose */
		print_debug(DBG_HIG_LVL, "IP: %.*s\n", len,
						  buffer + ovector[2*i]);

		char temp[IP_ADDR_LEN+1];

		memset(temp, '\0', sizeof(temp));
		/* Copy IP address */
		snprintf(temp, sizeof(temp), "%.*s", len, buffer + ovector[2*i]);

		/* Insert in list */
		insertNewIP(temp, ips);	
	}

	return ANON_SUCCESS;
}
