#include <loganon/ip_anon.h>
#include <loganon/random.h>
#include <uthash/uthash.h>





int loganon_ip_anon (int argc, char *argv[]){
  int i = 0,j=0;
	char *backup = NULL;
	char *key = malloc(14*sizeof(char));
  struct addr ip,*newip;
  char * buffer;

  struct ip_table *history;


  loganon_random_ultraweak_symkey(key,14);
  struct node *ip_list = (struct node *) new_ip_list();
  ip_list->prox = NULL;
  ip_list->index = 0;
  ip_list->field_value=0;

  struct ip_node *hash_table = (struct ip_node *) loganon_hash_table();
  struct addr *print_ip = NULL, *print_ip1 = NULL;
  print_ip = (struct addr *)  malloc(sizeof(struct addr));
  print_ip1 = (struct addr *) malloc(sizeof(struct addr));

	if (argc > 1){
		for ( i=1; i < argc;i++) { 

			printf("Argument \t %d -> \t %s\t", i,argv[i]);

  
      
			addr_aton(argv[i],&ip);
			printf("\t \t Network Format %u\t", ip.addr_ip);
			
			
//			ipv4_coherently_anon(ip,ip_list);

			memcpy (print_ip,&ip,sizeof(ip)); //copying the original ip;
			print_ip->addr_ip = loganon_ipv4_hash_anon(hash_table,ip.addr_ip);
			printf("\t HASH -> %s\t \n", addr_ntoa(print_ip));

			memcpy (print_ip1,&ip,sizeof(ip)); //copying the original ip;
			print_ip1->addr_ip = loganon_black_marker(ip.addr_ip,2);
			printf("\t BLACK -> %s\n", addr_ntoa(print_ip1));
			
			//Field Black Marker
			/*newip = ipv4_black_marker(ip,1);
			printf("\t Field Black Marker -> 1 field:  %s\n", addr_ntoa(newip));
			
			newip = ipv4_black_marker(ip,2);
			printf("\t Field Black Marker -> 2 fields:  %s\n", addr_ntoa(newip));
			
			//Fields Rotation Test
			
			newip=ipv4_field_rotation(ip,1);
			printf("\t Field Bit rotation -> 1 fields:  %s\n", addr_ntoa(newip));      
			
			
			
			printf("\n\t String Operations also implemented\n\n");
					printf("\t Truncated: %s\n", (char *) truncation(argv[i], 5)); /* leave 5 */
	//				printf("\t Random Permutation (need hash tables to not duplicate: %s\n", (char *) random_permutation()); 
					/* 3 for last field, 2 for two last fields, 1 for 3 last fields and 0 for all fields */
			/*backup = malloc(sizeof(char) * strlen(argv[i]));
			strcpy(backup, argv[i]);
			printf("\t Black marked with 2 fields: %s\n", (char *) black_marker(argv[i],2)); /* 3 for last field, 2 for two last fields, 1 for 3 last fields and 0 for all fields */
			//free(backup);
	     

		}
    }
    loganon_destruct_hash(hash_table);
}


//==========================================================================
//Todo: Above is old, remove that...
//==========================================================================
/* linked list functions */
struct node *new_ip_list (){
	struct node * tmp;
	tmp = (struct node *) malloc(sizeof(struct node));
	tmp->index = tmp->field_value = 0;
	tmp->prox=NULL;
}

unsigned long int search_and_insert(unsigned long int value, struct node * head, struct node * current,struct node * last){

	//printf("\nValue -> %lu",value);
	if (current == NULL){
		current = malloc(sizeof(struct node));
		current->prox=NULL;
		current->index=value;
		current->field_value=new_unique_ip(head);
		last->prox=current;
		return current->field_value;
	}


	//printf("\nIndex -> %lu",current->index);

	if (current->index == value){
		printf("\n\nMATCH! \n");
		put_on_top(head,current,last);
		return current->field_value;
	}
	else{
	//	printf("\nHERE!");
		if(current->prox!=NULL){
			return search_and_insert(value, head, (struct node *) current->prox, current);
			}
		else{
			struct node *new_node = malloc(sizeof(struct node));
			new_node->prox =  NULL;
			new_node->index = value;
			new_node->field_value = new_unique_ip(head);
			current->prox=new_node;
			return new_node->field_value;
		
		}
	
	
	}

}

unsigned long int new_unique_ip(struct node * head){
	unsigned long int newValue = 0;

	newValue = loganon_random_ip();
	while(search(head,newValue) == -1)
		newValue = loganon_random_ip();
	return newValue;



}

int search(struct node *head, unsigned long int value){
	if (head == NULL){
		//printf("\n\t\t First execution paused %lu ",value);
		return 0;}


	if (head->field_value == value) return -1;
	else return search((struct node *) head->prox, value);
}






void put_on_top(struct node * head, struct node * current, struct node * last){


	if(head->prox != last->prox){
		last->prox=current->prox;
		current->prox = head->prox;
		head->prox=current;
		}

}
//END
//===============================================================================



//Black Marker

/** 
 * struct addr ip black marker, rotate fields "int fields" times
 * @param struct addr ip (libdnet)
 * @param int fields
 * @return black marker struct addr ip
 */

struct addr * loganon_ipv4_black_marker (struct addr ip, int fields){
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

/**
 * \brief Gets and ip in struct addr (libdnet) format and rotate fields "int fields" times
 * \param struct addr ip
 * \param int fields
 */
struct addr * loganon_ipv4_field_rotation (struct addr ip, int fields){
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



/**
 * \brief Truncate the given char ip
 * \param ip in string format
 * \param the new len of string
 * \return a pointer to the new ip string
 */

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





/**
 * \brief Black marker, anonymize the entire field or just part of it 
 * \param Ip in string format
 * \param number of octets 
 * \return The new black marked ip in char format
 */


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



/**
 * \brief Anonymize the entire field or just part of it 
 * \param unsigned int ip - Ip for black mark
 * \param octet_number - Number of octets to mark
 * \return Black marked Ip
 */

unsigned int * loganon_black_marker(unsigned int ip, int octet_number){
	unsigned int mask = 0xFFFFFFFF;

	if (octet_number < 0)
		return ip;

	mask = mask >> (octet_number * 8);
	return ip & mask;

}



 
//============================Deprecated====================\\
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

//===========================================================\\



/**
 * \brief Creates new hash table. This is the handler for all ip_anon anonymization functions
 * \return struct ip_node Hash Table Handler
 */


struct ip_node * loganon_hash_table(){
	struct ip_node *temp = NULL, *temp2 = NULL, *new =NULL, *secondary = NULL;
	//Main index
	new = (struct ip_node *) malloc(sizeof(struct ip_node));
	memset(new, 0 , sizeof(struct ip_node));
	new->index = 0;
	new->newValue = 0;
	HASH_ADD(hh2,temp2, newValue, sizeof(unsigned int) , new);
	
	new->old_by_new = temp2;

	HASH_ADD(hh1, temp, index, sizeof(unsigned int), new);
	return temp;
}

/**
 * \brief Free all memory ocupied by hash table
 * \param The hash_table head node
 */

void loganon_destruct_hash(struct ip_node *hash_table){
	
	struct ip_node *tmp;
	while(hash_table) {
		tmp = hash_table;          /* copy pointer to first item     */
		HASH_DELETE(hh1, hash_table,tmp);  /* delete; users advances to next */
		free(tmp);            /* optional- if you want to free  */
	      }



}

int add_to_hash(unsigned long int key, unsigned long int newValue){
	return 0;

} 

/**
 * \brief Return a new hash node or the node foundend in hash table
 */

struct ip_node * loganon_new_hash_node(struct ip_node *hash_table, unsigned long int key, unsigned long int newValue, struct ip_node *zero_node){
	struct ip_node *node = NULL, *temp=NULL;
	HASH_FIND(hh2, zero_node->old_by_new, &newValue, sizeof(unsigned int), temp);
	if (temp)
		return NULL;

	node = malloc(sizeof(struct  ip_node));
	memset(node, 0, sizeof(struct ip_node)); /* The documentation of uthash requires zero fill */
	node->index = key;
	node->newValue = newValue;
	return node;

}


/**
 * \brief Return a new random ip, or an already used ip on anonymization proccess
 *
 * \param A utHash table, network format ip
 * \return a coherently ip, using hash table to verify
 */


unsigned long int loganon_ipv4_hash_anon(struct ip_node *hash_table, unsigned long int ind){
	struct ip_node *tmp=NULL, *tmp1=NULL, *newNode = NULL;
	unsigned int zero = 0;
	HASH_FIND(hh1, hash_table, &ind, sizeof(unsigned int) , tmp);
	if (tmp){
		return tmp->newValue;
		}
	else{
		
		HASH_FIND(hh1,hash_table, &zero, sizeof(unsigned int), tmp);
		do{
			newNode = (struct ip_node *) loganon_new_hash_node(hash_table, ind,loganon_strong_random_ip(), tmp);
		}while (newNode==NULL);
		tmp1 = tmp->old_by_new;	
		newNode-> old_by_new = tmp->old_by_new;
		HASH_ADD(hh1, hash_table, index, sizeof(unsigned int),newNode);
		HASH_ADD(hh2, tmp->old_by_new, newValue, sizeof(unsigned int), newNode);
		return newNode->newValue;
		}
}






