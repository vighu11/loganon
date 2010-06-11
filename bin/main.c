#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

static void print_help(int argc, char **argv)
{
	printf("Syntax: %s [command] file\n", argv[0]);
	printf("  command is:\n");
	printf("    --pcre 'regex'\n");
	printf("    --pcap\n");
	printf("\n");

	return 0;
}

static void parse_cmdline(int argc, char **argv)
{

	if (argc < 2) {
		print_help(argc, argv);
	}

}

int main(int argc, char **argv)
{

	parse_cmdline(argc, argv);

	return 0;
}
