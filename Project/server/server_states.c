
#include <stdio.h>
#include <stdlib.h>
#include "server_cases.c"

//TODO handle error cases,



void hello_server (FILE* log_server, char * ciphersuites_to_use, char * random_from_client, char * random_from_server){

	/* for the moment we suppose the client can use all 4 types of protocol */

	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	// Read data from channel
	read_channel (channel, received_message);
	fclose(channel);
	// Save it in log_server
	send_message (log_server, 2, receiving, received_message);
	fprintf(log_server, "\n\n");
	// Get the random from the client
	get_random_block(received_message,random_from_client);
	// Chose the best ciphersuite avilable
	chose_best_ciphersuite (received_message, ciphersuites_to_use);
	// Generate Random part
	random_from_server = gen_rdm_bytestream(RANDOM_DIM_HELLO);
	// Send Hello Server to the Client
	channel = fopen(link_channel,"w");
	send_message (channel, 5, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLO, random_from_server, ciphersuites_to_use);
	// Save it in log_server
	send_message (log_server, 6, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLO, random_from_server, ciphersuites_to_use);
	fprintf(log_server, "\n\n");
	fclose(channel);
	free(received_message);
}

void send_certificate(FILE* log_server,char * ciphersuite_to_use){
	  
	// Allocate memory to contain the certificate
	char * certificate = calloc(BUF_SIZE+1,sizeof(char));
	// Read the certificate (yes... 'read_channel' is an abusing of name)
	certificate = get_certificate();
	// Send message to the channel
	FILE* channel = fopen(link_channel,"w");
	send_message (channel, 4, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVER_CERTIFICATE, certificate);
	fclose(channel);
	// Save message in log_server
	send_message (log_server, 5, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVER_CERTIFICATE, certificate);
	fprintf(log_server, "\n\n");
	free(certificate);
}


int hello_done(FILE* log_server){

	// Send message to the channel
	FILE* channel = fopen(link_channel,"w");
	send_message (channel, 3, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLODONE);
	fclose(channel);
	// Save message in log_server
	send_message (log_server, 4, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLODONE);
	fprintf(log_server, "\n\n");

	return 1;
}



int receive_exchange_key(FILE * log_server, char * ciphersuite_to_use, char * premaster_secret){

	if (atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA1) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA2)){
			//DEVO CAPIRE ANCORA BENE COSA FARE CON TLS_DH_RSA
		return decrypt_secret_RSA(log_server, premaster_secret);
	}
	else 
		return 0;
}









