/*
 *	Prototypes for loganon_pcre
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_PCRE_H
#define LOGANON_PCRE_H

#include "loganon_errors.h"
#include "loganon_structs.h"

/*
 * Retrieve IPs from buffer
 * @param ips IPs linked list
 * @param buffer buffer we wants search IPs into
 */
int8_t pcre_search_ip(struct ip_anon **ips, const char *buffer);

#endif
