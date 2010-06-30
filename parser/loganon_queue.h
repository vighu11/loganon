/*
 *	Data structures used by Loganon
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_QUEUE_H
#define LOGANON_QUEUE_H

#include <inttypes.h>

#include "loganon_errors.h"
#include "loganon_structs.h"

/*
 * Insert a new IP in list
 * @return -1 if insertion fails, 0 if IP is already inserted, otherwise 1
 */
int8_t insertNewIP(const char* original, struct ip_anon** list);

#endif
