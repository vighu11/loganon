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
 * @return ANON_FAIL if file doesn't exist or is unsupported
 */
int8_t initLoganon(const char *filename);

#endif
