#include <loganon/random.h>
#include <time.h>
#include <stdlib.h>

/* An algorithm to generate a random symetric key */
void loganon_random_ultraweak_symkey(char *s, const int len) {
	int i = 0;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

unsigned long int loganon_random_ip(){
	unsigned long int field1=0, field2=0,field3=0,field4=0;
	srand ( time(NULL) );
	field1 = rand() % 254;
	srand ( time(NULL) );
	field2 = rand() % 254 << 8;
	srand ( time(NULL) );
	field3 = rand() % 254 << 16;
	srand ( time(NULL) );
	field4 = rand() % 254 << 24;
    /* generate secret number: */
	return field1+field2+field3+field4;    	


}
