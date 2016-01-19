
#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"
#include "../common/crypto2.c"

//TODO handle error cases,

const char receiving[13] = "**client** :";
const char sending[13] = "**server** :"; 
const char link_channel[20] = "./common/channel.txt";




void chose_best_ciphersuite(char * message, char * best_chipersuite){

	int n_ciphersuite = get_n_of_blocks(message)-3;
	int ciphersuites[n_ciphersuite];
	int best;
	for (int i = 0; i < n_ciphersuite; ++i){
		ciphersuites[i] = atoi(get_nth_block(message,4+i));
	}
	best = ciphersuites[0];
	for (int i = 1; i < n_ciphersuite; ++i)
	{
		if (best<ciphersuites[i]){
			best = ciphersuites[i];
		}
	}
	sprintf(best_chipersuite, "%d", best);
}




void server_states_0 (FILE* log_server, char * ciphersuites_to_use, char * random_from_client){

	/* for the moment we suppose the client can use all 4 types of protocol */

	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE,sizeof(char));
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
	char * random_part = calloc(32, sizeof(char));
	random_part = gen_rdm_bytestream(32);
	// Send Hello Server to the Client
	channel = fopen(link_channel,"w");
	send_message (channel, 4, TLS_HANDSHAKE, TLS_SERVERHELLO, random_part, ciphersuites_to_use);
	// Save it in log_server
	send_message (log_server, 5, sending, TLS_HANDSHAKE, TLS_SERVERHELLO, random_part, ciphersuites_to_use);
	fprintf(log_server, "\n\n");
	fclose(channel);
	free(received_message);
}

void server_state_1(FILE* log_server,char * ciphersuite_to_use){
	  
	// Allocate memory to contain the certificate
	char * certificate = calloc(BUF_SIZE,sizeof(char));
	// Read the certificate (yes... 'read_channel' is an abusing of name)
	certificate = get_certificate();
	// Send message to the channel
	FILE* channel = fopen(link_channel,"w");
	send_message (channel, 3, TLS_HANDSHAKE, TLS_SERVERHELLO, certificate);
	fclose(channel);
	// Save message in log_server
	send_message (log_server, 4, sending, TLS_HANDSHAKE, TLS_SERVERHELLO, certificate);
	fprintf(log_server, "\n\n");
	free(certificate);
}











