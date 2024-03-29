/*
 *	Prototypes for loganon_parser
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_PARSER_H
#define LOGANON_PARSER_H

#include <inttypes.h>

#include "loganon_errors.h"

/*
 * Open file for anonymization
 * @param filename name of file we want anonymize
 * @param filenameOut name of new file after anonymization
 * @return ANON_FAIL if file doesn't exist or is unsupported
 */
int8_t initLoganon(const char *filenameIn, const char *filenameOut);

/*
 * Apply anonymization on sensitive data
 * @param level level of anonymization
 */
int8_t loganonAnonymize(uint8_t level);

/*
 * Close handles and free memory
 * @return ANON_FAIL if no file has been successfully opened
 */
int8_t terminateLoganon();

#endif
