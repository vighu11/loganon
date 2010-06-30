/*
 *	Functions for lists
 *	Authors: Guillaume TOURON
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "loganon_queue.h"


static int8_t checkIfIPExists(const char* original, struct ip_anon* list)
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
 * Insert a new IP in list
 * @return -1 if insertion fails, 0 if IP is already inserted, otherwise 1
 */
int8_t insertNewIP(const char* original, struct ip_anon** list)
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
