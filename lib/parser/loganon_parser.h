/*
 *	Prototypes for loganon_parser
 *	Authors: Guillaume TOURON
 */

#ifndef LOGANON_PARSER_H
#define LOGANON_PARSER_H

#include <inttypes.h>

#include "loganon_errors.h"

/**
 * \briefOpen file for anonymization
 * \param filename name of file we want anonymize
 * \param filenameOut name of new file after anonymization
 * \return ANON_FAIL if file doesn't exist or is unsupported
 */
extern
int8_t loganon_init(const char *filenameIn, const char *filenameOut);

/**
 * \brief Apply anonymization on sensitive data
 * \param level level of anonymization
 * \return ANON_SUCCESS if anonymization succeeded, otherwise ANON_FAIL
 */
extern
int8_t loganon_anonymize(uint8_t level);

/**
 * \brief Close handles and free memory
 * \return ANON_FAIL if no file has been successfully opened
 */
extern
int8_t loganon_terminate();

#endif
