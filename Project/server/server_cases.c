#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"
#include "../common/crypto2.c"

const char receiving[13] = "**client** :";
const char sending[13] = "**server** :"; 
const char link_channel[] = "./common/channel.txt";
const char * link_prvkey = "./server/RSA_privkey.pem";
const int RANDOM_DIM_HELLO = 32;
const int RANDOM_DIM_KEY_EXCHANGE = 46;
const int PREMAS_SECRET_POSITION = 4;


int decrypt_secret_RSA(FILE * log_server, char * premaster_secret){

	char * encrypted_pm_secret = calloc(BUF_SIZE,sizeof(char));
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Save message in log_server
	fprintf(log_server, "%s\t", receiving);
	for(int i = 0; i<(265+6); i++){
		fprintf(log_server, "%c", received_message[i]);
	}
	fprintf(log_server, "\n\n");
	// extact the encrypted premaster_secret
	encrypted_pm_secret = get_nth_block(received_message,PREMAS_SECRET_POSITION);
	// Decrypt
	if(-1 == TLS_RSA_private_decrypt((unsigned char *) encrypted_pm_secret,256,link_prvkey, (unsigned char *) premaster_secret)){
		printf("SERVER: Private Decrypt failed ");
	}
	//free(received_message); NON GLI PIACE IL FREE
	return 1;
}