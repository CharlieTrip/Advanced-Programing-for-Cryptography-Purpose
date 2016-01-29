#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>

int hexToString(unsigned char *hexstring, unsigned char * bytearray){

    uint8_t str_len = strlen((char *)hexstring);

    for (int i = 0; i < (str_len / 2); i++) {
        sscanf((char *) hexstring + 2*i, "%02x", (unsigned int *) &bytearray[i]);
    }

    return 0;
}


int main(){

	unsigned char * step0;
	int * step1;
	char * step2;
	// Creating the first seed
	char seed[] = "aneleddumanuedduquantoebelloangeleddu";
	char secret[] = "123456789012345678901234";
	// first HMAC
	step0 = HMAC(EVP_sha1(), secret, strlen(secret), (const unsigned char *) seed, strlen(seed), NULL, NULL);
	FILE * file = fopen("./test/del.txt","w");
	//fprintf(file, "0x" );
	for (int i = 0; i < 20; ++i){
	  	fprintf(file, "%02x", step0[i]);
	}
	for (int i = 0; i < 20; ++i){
	  	fscanf(file,"%02x",step1[i]);
	}
	step1 = (char*) step1;
	fprintf(file,"\n\n\n");
	for (int i = 0; i < 20; ++i){
	  	fprintf(file, "%c", step0[i]);
	}
	fprintf(file,"\n\n\n");
	//hexToString((unsigned char*) step1,(unsigned char*) step2);
	for (int i = 0; i < 20; ++i){
	  	fprintf(file, "%c", step1[i]);
	}
	fclose(file);
}






