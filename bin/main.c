#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <loganon/general.h>

#define LOGANON_TOOL_VERSION "0.1"

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
#define LONGOPT_ARG_NONE 0
#define LONGOPT_ARG_REQUIRED 1
#define LONGOPT_ARG_OPTIONAL 2

	char *valid_options = "?hr:p:V";
	int option_index = -1;

	char ch;

	static struct option long_options[] =
		{
			{"version", LONGOPT_ARG_NONE, NULL, 'V'},
			{"help", LONGOPT_ARG_NONE, NULL, '?'},
			{0, 0, 0, 0}
		};



	if (argc < 2) {
		print_help(argc, argv);
	}

	while ((ch = getopt_long(argc, argv, valid_options, long_options, &option_index)) != -1)
	{
		switch (ch)
		{
		case 'V':
			printf("Loganon tool version: %s\n  library version: %d.%d.%d (%s)\n", LOGANON_TOOL_VERSION, LOGANON_VERSION_MAJOR, LOGANON_VERSION_MINOR, LOGANON_VERSION_MICRO, LOGANON_SCMID);
			break;
		case '?':
			print_help(argc, argv);
			break;
		}
	}

}

int main(int argc, char **argv)
{

	parse_cmdline(argc, argv);

	return 0;
}
