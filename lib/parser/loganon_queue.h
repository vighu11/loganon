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
extern
int8_t insert_new_ip(const char* original, struct ip_anon **list);

/*
 * Retrieve anonymized IP from the original one
 * @param originalIP IP not anonymized
 * @param list IPs list
 * @return anonymized IP if original IP is found, otherwise NULL
 */
extern
uint32_t get_anonymized_ip(const char *originalIP, struct ip_anon *list);

/*
 * Free all IPs inserted in list
 * @param list IPs list to free
 */
extern
void free_list_ips(struct ip_anon *list);

#endif
