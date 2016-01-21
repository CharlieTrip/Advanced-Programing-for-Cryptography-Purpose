#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"
#include "../common/crypto2.c"


//TODO handle error cases, 

const char sending[13] = "**client** :";
const char receiving[13] = "**server** :"; 
const char link_channel[20] = "./common/channel.txt";



int client_hello (FILE* log_client){

	/* for the moment we suppose the client can use all 4 types of ciphersuite */
	// Read the channel
	char * received_message = calloc(BUF_SIZE,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	read_channel (channel, received_message);
	fclose(channel);
	// save received message on log_client
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	// Verify if a Hello_request is present
	if(!strcmp(get_nth_block(received_message,2), TLS_HELLOREQUEST)){
		channel = fopen (link_channel,"w");
		// Generate Random part
		char * random_part = calloc (32, sizeof(char));
		random_part = gen_rdm_bytestream (32);
		// Send Hello Client to the Server
		send_message (channel, 11, TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, 
			TLS_DH_RSA_WITH_AES_128_CBC_SHA, TLS_DH_RSA_WITH_AES_256_CBC_SHA, 
			TLS_DH_RSA_WITH_AES_128_CBC_SHA256, TLS_DH_RSA_WITH_AES_256_CBC_SHA256, 
			TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, 
			TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256);
		// Save it in log_client
		send_message (log_client, 12, sending, TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, 
			TLS_DH_RSA_WITH_AES_128_CBC_SHA, TLS_DH_RSA_WITH_AES_256_CBC_SHA, 
			TLS_DH_RSA_WITH_AES_128_CBC_SHA256, TLS_DH_RSA_WITH_AES_256_CBC_SHA256, 
			TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, 
			TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256);
		fprintf(log_client, "\n\n");
		fclose (channel);
		free(received_message);
		return 1;
	}
	else
	{
		printf("Error: expected a Hello_request, found an unexpected mesage");
		return 0;
	}
}


int client_receiving_server_hello (FILE* log_client, char * ciphersuites_to_use, char * random_from_server){

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
	return 1;
}


int client_receiving_certificate (FILE* log_client){

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
	return 1;
}
























