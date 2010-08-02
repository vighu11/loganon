/*
 *	Macros for debugging
 *	Authors: Guillaume TOURON
 */

#ifndef DEBUG_UTILS_H
#define DEBUG_UTILS_H

/* Debug levels for print */
#define DBG_LOW_LVL 1
#define DBG_MED_LVL 2
#define DBG_HIG_LVL 3

/* Debug level for Loganon debuging */
#define DBG_LEVEL DBG_HIG_LVL

/*
 * Print debug message if level >= DBG_LEVEL
 */
#define print_debug(level, ...) 		\
							\
	if(level >= DBG_LEVEL)    		\
		fprintf(stderr, __VA_ARGS__);

/* TODO: Create a new macro for error printing */

#endif
