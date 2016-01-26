#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"
#include "../common/crypto2.c"


//TODO handle error cases, 

const char sending[13] = "**client** :";
const char receiving[13] = "**server** :"; 
const char link_channel[20] = "./common/channel.txt";



void hello_client (FILE* log_client){

	/* for the moment we suppose the client can use all 4 types of ciphersuite */

	FILE* channel = fopen (link_channel,"w");
	// Generate Random part
	char * random_part = calloc (32, sizeof(char));
	random_part = gen_rdm_bytestream (32);
	// Send Hello Client to the Server
	send_message (channel, 7, TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, TLS_DH_RSA_SHA1, TLS_DH_RSA_SHA2, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);
	// Save it in log_client
	send_message (log_client, 8, sending, TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, TLS_DH_RSA_SHA1, TLS_DH_RSA_SHA2, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);
	fprintf(log_client, "\n\n");
	fclose (channel);
}


void receive_hello_server (FILE* log_client, char * ciphersuites_to_use, char * random_from_server){

	char * received_message = calloc(BUF_SIZE,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Save it in log_client
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	// Get the random from the client
	get_random_block(received_message,random_from_server);
	// Get the ciphersuite to use (choosed by the server)
	sprintf (ciphersuites_to_use, "%d", atoi(get_nth_block(received_message,4)));
}


void receive_certificate (FILE* log_client){

	char * certificate = calloc(BUF_SIZE,sizeof(char));
	char * received_message = calloc(BUF_SIZE,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Save it in log_client
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	// certificate = get_nth_block(received_message,2);
	// Open a .pem file to write the certificate
	FILE *cert_file = fopen("./client/cert-file.pem", "w");
	// Extract the certificate from the received message and write it in a .pem file
	certificate = get_nth_block(received_message,3);
	PEM_write_X509(cert_file, string_to_X509(certificate));
 	free(received_message);
 	//free(certificate); NON GLI PIACE IL FREE
 	fclose(cert_file);
	get_pubkey();
}


int exchange_key(FILE* log_client, char * ciphersuite_to_use){

	

	return 1;
}

int change_cipher(FILE* log_client, char * secret, int sha){


	return 1;

	/* for the moment we suppose the client can use all 4 types of ciphersuite */

	FILE* channel = fopen (link_channel,"w");
	FILE* tmp_log = log_client;



	// Send ChangeCipherSuite to the Server
	send_message (channel, 1, TLS_CHANGECIPHERSPEC);
	send_message (log_client, 2, sending , TLS_CHANGECIPHERSPEC);
	fprintf(log_client,  "\n\n");
	
	fclose (channel);

	// 
	//  Server must save the log until here to check after
	//


	// Generate Hash of the log
	char * hashed_log; 

	if (sha == 1){
		hashed_log = calloc (40 , sizeof(char));
		HMAC_SHA1_file(tmp_log,secret,(int)strlen(secret),(unsigned char *)"",hashed_log);
	}
	else {
		hashed_log = calloc (64 , sizeof(char));
		HMAC_SHA2_file(tmp_log,secret,(int)strlen(secret),(unsigned char *)"",hashed_log);
	}



	// Send finish
	send_message (channel, 3 ,TLS_HANDSHAKE , TLS_FINISHED , hashed_log);
	send_message (log_client, 4 , sending, TLS_HANDSHAKE , TLS_FINISHED , hashed_log);
	fprintf(log_client,  "\n\n");
	


	return 0;
}





















