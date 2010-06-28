#include <stdio.h>

#include "loganon_parser.h"
#include "loganon_parser_pcap.h"

int main(int argc, char *argv[])
{
	if(argc < 2) return 0;

	initLoganon(argv[1]);

	return 0;
}
