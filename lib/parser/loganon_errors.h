/*
 *	Return values used by Loganon
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_ERRORS_H
#define LOGANON_ERRORS_H

/*
 * Macro for processing errors
 */
#define ANON_PROCESS_ERROR(msg)				\
		if(ret == ANON_FAIL) {				\
									\
			print_debug(DBG_HIG_LVL, msg);	\
			return ret;					\
		}

/*
 * Return values for parsers
 */
#define ANON_FAIL     -1
#define ANON_SUCCESS   0

/*
 * Return values for lists
 */
#define LIST_FAIL		-1
#define LIST_EXIST	 0
#define LIST_SUCCESS	 1

#endif
