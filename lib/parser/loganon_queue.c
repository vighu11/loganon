/*
 *	Functions for lists
 *	Authors: Guillaume TOURON
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "loganon_queue.h"


/*
 * Check if an IP has already be found
 * @param original original IP
 * @param list pointer on the IPs list
 * @return LIST_EXIST if IP is already known, otherwise LIST_SUCCESS
 */
static 
int8_t checkIfIPExists(const char* original, struct ip_anon *list)
{
	struct ip_anon *current = list;

	/* Check if original is in list */
	for(; current; current = current->next_ip) {

		if(!strcmp(original, current->ip_original))
			return LIST_EXIST;
	}

	return LIST_SUCCESS;
}

/*
 * Insert a new IP in list cheking if it's a new IP or not
 * @return LIST_EXIST if IP has already been inserted, otherwise LIST_SUCCESS
 */
extern
int8_t insert_new_ip(const char *original, struct ip_anon **list)
{
	struct ip_anon *current = *list;

	if(!(*list)) {

		/* Add new entry */
		*list = malloc(sizeof(struct ip_anon));
		assert(*list != NULL);

		current = *list;
	}
	else {

		/* Check if insertion is needed */
		int8_t ret = checkIfIPExists(original, *list);
		if(ret == LIST_EXIST)
			return ret;

		/* Go to the end of list */
		for(; current->next_ip; current = current->next_ip);

		/* Add new entry at the end of list */
		current->next_ip = malloc(sizeof(struct ip_anon));
		assert(current->next_ip != NULL);

		current = current->next_ip;
	}

	/* Save original ip */
	if(strlen(original) > IP_ADDR_LEN) {

		/* Should never happen... */

		strncpy(current->ip_original, original, IP_ADDR_LEN);
		/* Add null on last position */
		current->ip_original[IP_ADDR_LEN] = '\0';
	}
	else {
		strncpy(current->ip_original, original, strlen(original));
		/* Add null */
		current->ip_original[strlen(original)] = '\0';
	}

	current->next_ip = NULL;

	return LIST_SUCCESS;
}

/*
 * Retrieve anonymized IP from the original one
 * @param originalIP IP not anonymized
 * @param list IPs list
 * @return anonymized IP if original IP is found, otherwise NULL
 */
extern
uint32_t get_anonymized_ip(const char *originalIP, struct ip_anon *list)
{
	struct ip_anon *current = list;

	/* Display each entry */
	for(; current; current = current->next_ip) {
		/* If original IP matches */
		if(!strcmp(current->ip_original, originalIP))
			return inet_addr(current->ip_anonymized);
	}

	return 0;
}

/*
 * Free all IPs inserted in list
 * @param list IPs list to free
 */
extern
void free_list_ips(struct ip_anon *list)
{
	if(list) {

		/* Recursive */
		free_list_ips(list->next_ip);
		free(list);
	}
}
