#include <stdio.h>
#include <stdlib.h>
#include "client_cases.c"


//TODO handle error cases, 

void hello_client (FILE* log_client){

	/* for the moment we suppose the client can use all 4 types of ciphersuite */

	FILE* channel = fopen (link_channel,"w");
	// Generate Random part
	char * random_part = calloc (RANDOM_DIM_HELLO+1, sizeof(char));
	random_part = gen_rdm_bytestream (RANDOM_DIM_HELLO);
	// Send Hello Client to the Server
	send_message (channel, 6, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);
	// Save it in log_client
	send_message (log_client, 7, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);
	fprintf(log_client, "\n\n");
	fclose (channel);
}


void receive_hello_server (FILE* log_client, char * ciphersuite_to_use, char * random_from_server){

	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
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
	sprintf (ciphersuite_to_use, "%s", get_nth_block(received_message,CIPHERSUITE_TO_USE_POSITION));
}


void receive_certificate (FILE* log_client){

	char * certificate = calloc(BUF_SIZE+1,sizeof(char));
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Save it in log_client
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	// Open a .pem file to write the certificate
	FILE *cert_file = fopen(link_certificate, "w");
	// Extract the certificate from the received message and write it in a .pem file
	certificate = get_nth_block(received_message,CERTIFICATE_POSITION);
	PEM_write_X509(cert_file, string_to_X509(certificate));
 	free(received_message);
 	//free(certificate); NON GLI PIACE IL FREE
 	fclose(cert_file);
	get_pubkey(link_public_key, link_certificate);
}


int exchange_key(FILE* log_client, char * ciphersuite_to_use, char * premaster_secret){

	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Write to log_client the received message
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	free(received_message);
	if (atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA1) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA2)){
			//DEVO CAPIRE ANCORA BENE COSA FARE CON TLS_DH_RSA
		return encrypt_secret_RSA(log_client, premaster_secret);
	}
	else 
		return 0;
}

























