#include <loganon/str_anon.h>
#include <loganon/random.h>
#include <openssl/evp.h>

/*
 * Test Funcion
 */

void loganon_str_test_all(char *arg){
	//A Function to test all methods of string anonymization
	char *md5Value = NULL, *sha1Value = NULL;
	
	printf("%s\n",arg);
	md5Value = (char *) loganon_md5_digest(arg, strlen(arg)*sizeof(char));
	printf("\tMD5SUM = %s \n",(char *)  md5Value);
	sha1Value = (char *) loganon_sha1_digest(arg, strlen(arg)*sizeof(char));

	printf("\tSHA1 = %s \n",(char *)  sha1Value);

	free(md5Value);
	free(sha1Value);

}

/*
 * Give a string and get your md5 digest as result
 * @param String
 * @param len of string
 * @return string digest pointer
 */

char * loganon_md5_digest (const void * text, int len){
	EVP_MD_CTX holder;
	unsigned char mdvalue[EVP_MAX_MD_SIZE], *temp=NULL;
	unsigned int mdlen;

	EVP_DigestInit(&holder, EVP_md5());

	EVP_DigestUpdate(&holder, text, (size_t) len);

	EVP_DigestFinal_ex(&holder, mdvalue, &mdlen);

	temp = (char *) return_as_hex(mdvalue,mdlen);


	EVP_MD_CTX_cleanup(&holder);
	return temp;
}

/*
 * Give a string and get your md5 digest as result
 * @param String
 * @param len of string
 * @return string digest pointer
 */
char * loganon_sha1_digest (const void * text, int len){

	int i;
	EVP_MD_CTX holder;
	unsigned char mdvalue[EVP_MAX_MD_SIZE], *temp=NULL;
	unsigned int mdlen;

	EVP_DigestInit(&holder, EVP_sha1());
	EVP_DigestUpdate(&holder, text, (size_t) len);

	EVP_DigestFinal_ex(&holder, mdvalue, &mdlen);

	temp = (char *) return_as_hex(mdvalue,mdlen);
	EVP_MD_CTX_cleanup(&holder);
	return temp;
}

char * return_as_hex (const unsigned char *digest, int len) {
  int i;
  char *hex,buffer[EVP_MAX_MD_SIZE]="\0",current[2];
    for(i = 0; i < len; i++){
       		 sprintf (current,"%02x", digest[i]);
		 strcat(buffer,current);
		 }
   hex = strdup(buffer);
   return hex;
}

