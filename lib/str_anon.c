#include <loganon/str_anon.h>
#include <loganon/random.h>
#include <openssl/evp.h>



void loganon_str_test_all(char *arg){
	//A Function to test all methods of string anonymization
	printf("%s\n",arg);
	char * md5value = loganon_md5_digest(arg, strlen(arg)*sizeof(char));
	printf("\tMD5SUM = %s \n", md5value);
	//free(md5value);

}



char * loganon_md5_digest (const void * text, int len){

	EVP_MD_CTX holder;
	unsigned char mdvalue[EVP_MAX_MD_SIZE], *temp;
	unsigned int mdlen;

	EVP_DigestInit(&holder, EVP_md5());

	EVP_DigestUpdate(&holder, text, (size_t) len);

	EVP_DigestFinal_ex(&holder, mdvalue, &mdlen);


	temp = return_as_hex(mdvalue,mdlen);


	EVP_MD_CTX_cleanup(&holder);
	return temp;
}






char * return_as_hex (const unsigned char *digest, int len) {
  int i;
  char * hex = (char *) calloc(len+1,sizeof(char) );
  hex[0]='\0';
  char buffer[10];
    for(i = 0; i < len; i++){
       		 sprintf (buffer,"%02x", digest[i]);
		 strcat(hex,buffer);
		 }
   return hex;
}

