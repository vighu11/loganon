/*
 *	Prototypes for loganon_parser_syslog
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_PARSER_SYSLOG_H
#define LOGANON_PARSER_SYSLOG_H

#include "loganon_errors.h"
#include "loganon_structs.h"

/*
 * Open syslog file
 * @param filenameIn name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist, otherwise ANON_SUCCESS
 */
int8_t anonSyslogOpen(const char *filenameIn, const char *filenameOut);

/*
 * Parse syslog file to find out sensitive data
 * @param ips pointer on a pointer on the IPs list
 * @return ANON_FAIL if search fails, otherwise ANON_SUCCESS
 */
int8_t anonSyslogSearchSensitiveData(struct ip_anon **ips)

#endif
