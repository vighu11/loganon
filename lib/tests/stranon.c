#include <stdio.h>

int main (int argc, char **argv){
	int i = 0;
	printf("Starting loganon Str anonymization demo...\n");
	for ( i; i<argc; i++){
		printf("Argument %d -> ",i);
		loganon_str_test_all(argv[i]);
	}

}
