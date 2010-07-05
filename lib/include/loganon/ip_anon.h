
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dumbnet.h>
//nclude <math.h>
//#include <openssl/lhash.h>
#include <uthash/uthash.h>

char * truncation ( char *, int);
char * black_marker(char *, int );
void swap(char *, int , int );
char * random_permutation();

struct ip_table * new_table();


typedef struct node{
	unsigned long int index;
	unsigned long int field_value;
	struct _node *prox;

}_node;


struct addr * ipv4_coherently_anon (struct addr ip, struct node *);
struct addr * ipv4_black_marker (struct addr, int);
struct addr * ipv4_field_rotation (struct addr, int);


unsigned long int new_unique_ip(struct node * head);


struct node * new_ip_list ();
void put_on_top(struct node * head, struct node * current, struct node * last);



/* Structures for UTHASH LIBRARY */
struct ip_node {
	unsigned long int index;
	unsigned long int newValue;
	UT_hash_handle hh;

};

struct ip_node *create_hash_table();
int add_to_hash(unsigned long int key, unsigned long int newValue);
struct ip_node *create_a_node(unsigned long int key, unsigned long int newValue);

unsigned long int using_hash_anon(struct ip_node *hash_table, unsigned long int old_ip);



