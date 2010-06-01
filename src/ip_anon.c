#include <stdio.h>
#include <string.h>
#include <stdlib.h>


char * truncation ( char *, int);
void gen_random(char *, const int);
char * black_marker(char *, int );
void swap(char *, int , int );
int permute(char *, int);
char * random_permutation();

int main (int argc, char *argv[]){
        int i = 0,j=0;
	char *backup = NULL;
	char *key = malloc(14*sizeof(char));
	gen_random(key,14);
	if (argc > 1){
		for ( i=1; i < argc;i++) { 
			printf("Argument %d -> %s\n", i,argv[i]);
			printf("   Truncated: %s\n", (char *) truncation(argv[i], 5)); /* leave 5 */
			printf("   Random Permutation (need hash tables to not duplicate: %s\n", (char *) random_permutation()); /* 3 for last field, 2 for two last fields, 1 for 3 last fields and 0 for all fields */
			backup = malloc(sizeof(char) * strlen(argv[i]));
			strcpy(backup, argv[i]);
			printf("   Black marked with 2 fields: %s\n", (char *) black_marker(argv[i],2)); /* 3 for last field, 2 for two last fields, 1 for 3 last fields and 0 for all fields */

			   for (j=0;j< 10;j++){
      				printf("   Testing depending permutation: %s\n",backup);
			   	permute(backup, strlen(backup));
				}

			free(backup);


                      }
                }
}

/* Truncate a string, newLen will be the point of truncation */
/* Example 192.168.1.1 -> 192.168.1.0 OR 10.1.1.1 */

char * truncation (char *ip, int newLen){
        int i = 0;
        if (newLen > sizeof(ip))
                newLen = sizeof(ip);
        char *newIp = malloc(newLen+1);
        for (i = 0; i < newLen; i++)
                newIp[i] = ip[i];
        newIp[i]='\0';;
        return newIp;
}

/* Black marker, anonymize the entire field or just part of it */
/* Input: Ip and number of octets to anonymize */
char * black_marker(char *ip, int octet_number){

	if (octet_number < 0)
		return NULL;
	octet_number*=-1;

	int counter = 0;
	char result[15] = {"\0"};
	char *field;

	field = strtok(ip,".");
	while (field!=NULL){
		if (octet_number >= 0)
			strcat(result,"255");
		else
			strcat(result,field); 
		if (counter < 3)
			strcat(result,".");
		field = strtok(NULL,".");
		octet_number++; counter++;
		}
	field = malloc(sizeof(char)*(strlen(result)) );
	strcpy(field, result);
	return field;

}



 

/* An algorithm to generate a random symetric key */
int get_random_field() {
	return rand() % 255;
}

/* An algorithm to generate a random permutation of Ip */
char * random_permutation(){
	int i = 0,n;
	char result[15]={ "\0" }, *result_pointer;
	char buffer[3];
	for (i=0; i < 4; i++){
		n=sprintf (buffer, "%d", get_random_field() );
		strcat(result,buffer);
		if ( i < 3)
			strcat(result,".");
		}
	result_pointer = malloc(sizeof(char)*(strlen(result)) );
	strcpy(result_pointer, result);
	return result_pointer;
}


/* An algorithm to generate a random symetric key */

void gen_random(char *s, const int len) {
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






/* Test for prefix-preserving permutation */
void swap(char *s, int a, int b)
{
   char temp=s[a];
   s[a] = s[b];
   s[b] = temp;
}


int permute(char *str, int len)
{
	int key=len-1;
	int newkey=len-1;

	/* The key value is the first value from the end which
	is smaller than the value to its immediate right        */

	while ((key > 0) && (str[key] <= str[key-1])) {
		key--; 
		}

	key--;

	/* If key < 0 the data is in reverse sorted order, 
	which is the last permutation.                          */

	if( key < 0 )
		return 0;

	/* str[key+1] is greater than str[key] because of how key 
	was found. If no other is greater, str[key+1] is used   */

	newkey=len-1;
	while( (newkey > key) && (str[newkey] <= str[key]) ){
		newkey--;
		}
	swap(str, key, newkey);

	/* variables len and key are used to walk through the tail,
	exchanging pairs from both ends of the tail.  len and 
	key are reused to save memory                           */
	len--;
	key++;
	/* The tail must end in sorted order to produce the
	next permutation.                                       */
	while(len>key){
		swap(str,len,key);
		key++;
		len--;
		}

	return 1;
}




