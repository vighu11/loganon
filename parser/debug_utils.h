/*
 *	Macros for debugging
 *	Authors: Guillaume TOURON
 */

#ifndef DEBUG_UTILS_H
#define DEBUG_UTILS_H

/* Debug level for loganon */
#define DBG_LEVEL 0

/* Debug levels for print */
#define DBG_LOW_LVL 1
#define DBG_MED_LVL 2
#define DBG_HIG_LVL 3

/*
 * Print debug message if level > DBG_LEVEL
 */
#define print_debug(level, ...) \
	if(level > DBG_LEVEL)   \
		fprintf(stderr, __VA_ARGS__);

#endif
