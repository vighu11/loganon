#include <loganon/random.h>

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


