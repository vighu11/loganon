
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dumbnet.h>
//nclude <math.h>
#include <openssl/lhash.h>


char * truncation ( char *, int);
char * black_marker(char *, int );
void swap(char *, int , int );
char * random_permutation();

struct ip_table * new_table();



struct addr * ipv4_coherently_anon (struct addr ip);
struct addr * ipv4_black_marker (struct addr, int);
struct addr * ipv4_field_rotation (struct addr, int);
