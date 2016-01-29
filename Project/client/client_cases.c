#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"
#include "../common/crypto2.c"

const char sending[] = "**client** :";
const char receiving[] = "**server** :"; 
const char link_channel[] = "./common/channel.txt";
const char * link_public_key = "./client/public_key.pem";
const char * link_certificate = "./client/cert-file.pem";
const int RANDOM_DIM_HELLO = 32;
const int RANDOM_DIM_KEY_EXCHANGE = 46;
const int CIPHERSUITE_TO_USE_POSITION = 5;
const int CERTIFICATE_POSITION = 4;



int encrypt_secret_RSA(FILE* log_client, char * premaster_secret){
// Allocating memory
	char * random_stream = calloc(RANDOM_DIM_KEY_EXCHANGE+1,sizeof(char));
	char * encrypted_secret = calloc(BUF_SIZE+1,sizeof(char));
	// get random part of the premaster_secret
	random_stream = gen_rdm_bytestream(RANDOM_DIM_KEY_EXCHANGE);
	// copy TLS version to the head of the premaster_secret
	memcpy(premaster_secret,TLS_VERSION,2);
	// add the random part previously obtained to the premaster_secret
	memcpy(premaster_secret+2,random_stream,46);
	// deallocating memory
	free(random_stream);
	// encrypt all with public key RSA sent by the server
	if(-1 == TLS_RSA_public_encrypt((unsigned char *) premaster_secret,strlen(premaster_secret),link_public_key,encrypted_secret))
	{
	    printf("Public Encrypt failed ");
	    return 0;
	}
	
	FILE* channel = fopen (link_channel,"w");
	// Send encrypted premaster_secret to the Server
	send_message (channel, 3, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTKEYEXCHANGE);
	fprintf(channel, "\t");
	// Save it in log_client
	send_message (log_client, 4, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTKEYEXCHANGE);
	fprintf(log_client, "\t");
	// I need to send the encryption byteXbythe since there can be also \0 char
	for(int i = 0; i<256; i++){
		fprintf(log_client, "%c", encrypted_secret[i]);
		fprintf(channel, "%c", encrypted_secret[i]);
	}
	fprintf(log_client, "\n\n");		
	fclose (channel);
	free(encrypted_secret);
	return 1;
}



