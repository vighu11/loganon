#include <stdio.h>
#include <stdlib.h>

#include "loganon_parser.h"
#include "loganon_parser_pcap.h"

/* Usage */
void usage(const char *prog)
{
	printf("** Test program for the parser\n" \
	       "** Usage: %s <pcap_in> <pcap_anonymized>\n", prog);

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	if(argc < 3) 
		usage(argv[0]);

	/* Loganon initialization */
	loganon_init(argv[1], argv[2]);
	
	/* Anonymize sensitive data	
	   Set level 1 for test */
	loganon_anonymize(1);

	/* Free memory and handles */
	loganon_terminate();

	return 0;
}