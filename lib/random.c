#include <loganon/random.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/rand.h>

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
	field4 = (random() % 4294967295 );
    /* generate secret number: */
	return field4;    	


}

unsigned long int loganon_strong_random_ip(){
	RAND_load_file("/dev/urandom", 1024);
	unsigned long int buf;
	RAND_bytes((char *) &buf,sizeof(unsigned long int));
	return buf % 429467295;


}
