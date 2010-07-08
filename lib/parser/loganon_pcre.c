/*
 *	Functions for regular expressions (pcre wrapper)
 *	Authors: Guillaume TOURON
 */

#include <pcre.h>

#include "debug_utils.h"

#include "loganon_queue.h"
#include "loganon_regex.h"

/*
 * Retrieve IPs from buffer
 * @param ips IPs linked list
 * @param buffer buffer we wants search IPs into
 */
int8_t pcre_search_ip(struct ip_anon **ips, const char *buffer)
{
	pcre *regex;
	/* PCRE error buffer */
	char *errbuf;

	/* Compile IPs-regex */
	regex = pcre_compile(argv[1], 0, (const char **)&errbuf, NULL, NULL);
	if(!regex) {

		print_debug(DBG_HIG_LVL, "pcre_compile error: %s\n", errbuf);
		return ANON_FAIL;
	}

	/* Apply compiled IPs-regex */
	
}
