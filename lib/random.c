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

	int r;
	int num;
	time_t now = time(NULL);
	if (now == (time_t) -1) {
		  /* handle error */
	  }
	 srandom(now); 


	unsigned long int field1=0, field2=0,field3=0,field4=0;
	//field1 = (random() % 254);
	//field2 = (random() % 254 )<< 8;
	//field3 = (random() % 254 )<< 16;
	field4 = (random() % 4294967295 );
    /* generate secret number: */
	return field4;    	


}
