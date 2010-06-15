#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dumbnet.h>
//nclude <math.h>

#include <loganon/random.h>

char * truncation ( char *, int);
char * black_marker(char *, int );
void swap(char *, int , int );
char * random_permutation();


struct addr * ipv4_black_marker (struct addr, int);
struct addr * ipv4_field_rotation (struct addr, int);

int loganon_ip_anon (int argc, char *argv[]){
  int i = 0,j=0;
	char *backup = NULL;
	char *key = malloc(14*sizeof(char));
  struct addr ip,*newip;
  char * buffer;

  loganon_random_ultraweak_symkey(key,14);
	if (argc > 1){
		for ( i=1; i < argc;i++) { 
			printf("Argument %d -> %s\n", i,argv[i]);


      
      addr_aton(argv[i],&ip);
      printf("Network Format %u\n", ip.addr_ip);


      //Field Black Marker
      newip = ipv4_black_marker(ip,1);
      printf("\t Field Black Marker -> 1 field:  %s\n", addr_ntoa(newip));

      newip = ipv4_black_marker(ip,2);
      printf("\t Field Black Marker -> 2 fields:  %s\n", addr_ntoa(newip));
     
      //Fields Rotation Test

      newip=ipv4_field_rotation(ip,1);
      printf("\t Field Bit rotation -> 1 fields:  %s\n", addr_ntoa(newip));      
      
      

      printf("\n\t String Operations also implemented\n\n");
			printf("\t Truncated: %s\n", (char *) truncation(argv[i], 5)); /* leave 5 */
			printf("\t Random Permutation (need hash tables to not duplicate: %s\n", (char *) random_permutation()); /* 3 for last field, 2 for two last fields, 1 for 3 last fields and 0 for all fields */
			backup = malloc(sizeof(char) * strlen(argv[i]));
			strcpy(backup, argv[i]);
			printf("\t Black marked with 2 fields: %s\n", (char *) black_marker(argv[i],2)); /* 3 for last field, 2 for two last fields, 1 for 3 last fields and 0 for all fields */
 			free(backup);
     

      }
    }
}


/* Working with libdumbnet */
struct addr * ipv4_black_marker (struct addr ip, int fields){
  unsigned long int expr1=0xFFFFFFFF, expr2=0;
  struct addr *newip = malloc(sizeof(struct addr));
  int i = fields;

  if (1 < fields > 5){ //Ip have at most 4 fields 
      printf("Wrong fields number in ipv4_black_marker");
      free(newip);
      return NULL;
      }
  else{
      expr1 = expr1 >> fields*8; //Shifting expr1 to right (ip is on little endian format)
      do{
          expr2 = expr2 + (1 << (4-i)*8);
          i--;
          }while(i>0);
      }

  memcpy (newip,&ip,sizeof(ip)); //copying the original ip
  newip->addr_ip = (newip->addr_ip & expr1) | expr2; //Adjust anonymized value to new IP
  return newip;
}


struct addr * ipv4_field_rotation (struct addr ip, int fields){
  unsigned long int expr1=0xFFFFFFFF, expr2=0;
  struct addr *newip = malloc(sizeof(struct addr));
  int i = fields;

  if (1 < fields > 5){ //Ip have at most 4 fields 
      printf("Wrong fields number in ipv4_field_rotation");
      free(newip);
      return NULL;
      }

  memcpy (newip,&ip,sizeof(ip)); //copying the original ip                                        for (i = 0; i < newLen; i++)
  newip->addr_ip = (newip->addr_ip << (fields*8)) | (newip->addr_ip >> 32-(fields*8));
  return newip;                                          
}



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
