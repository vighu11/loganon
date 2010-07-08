/*
 *	Functions for syslog file parsing
 *	Authors: Guillaume TOURON
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "loganon_pcre.h"
#include "loganon_queue.h"
#include "loganon_errors.h"

#include "debug_utils.h"


/* Syslog file handle for reading and writing */
static FILE *handleR, *handleW;

/*
 * Pcap files names
 */
static char *g_filenameIn, *g_filenameOut;

/*
 * Open syslog file
 * @param filenameIn name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist, otherwise ANON_SUCCESS
 */
int8_t anon_syslog_open(const char *filenameIn, const char *filenameOut)
{
	/* Open syslog file for parsing */
	handleR = fopen(filenameIn, "r");
	if(!handleR) {
		print_debug(DBG_HIG_LVL, "fopen error");
		/* Return failure */
		return ANON_FAIL; 
	}

	/* Allocate memory for filenameIn*/
	g_filenameIn = malloc(strlen(filenameIn) + 1);

	assert(g_filenameIn != NULL);

	/* Allocate memory for filenameOut */
	g_filenameOut = malloc(strlen(filenameOut) + 1);

	assert(g_filenameOut != NULL);

	/* Copy files names */
	strncpy(g_filenameIn, filenameIn, strlen(filenameIn) + 1);
	strncpy(g_filenameOut, filenameOut, strlen(filenameOut) + 1);

	return ANON_SUCCESS;
}

/*
 * Parse syslog file to find out sensitive data
 * @param ips pointer on a pointer on the IPs list
 * @return ANON_FAIL if search fails, otherwise ANON_SUCCESS
 */
int8_t anon_syslog_search_data(struct ip_anon **ips)
{
	

	return ANON_SUCCESS;
}
