
#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"
#include "../common/crypto2.c"

//TODO handle error cases,

const char receiving[13] = "**client** :";
const char sending[13] = "**server** :"; 
const char link_channel[20] = "./common/channel.txt";


int hello_request(FILE* log_server){
	// Send hello_request to the channel
	FILE* channel = fopen(link_channel,"w");
	send_message (channel, 2, TLS_HANDSHAKE, TLS_HELLOREQUEST);
	fclose(channel);
	// write hello_request on the server's log
	send_message (log_server, 3, sending, TLS_HANDSHAKE, TLS_HELLOREQUEST);
	fprintf(log_server, "\n\n");
	return 1;
}


int chose_best_ciphersuite(char * message, char * best_chipersuite){

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
	return 1;
}


int is_needed_keyexchange(char * ciphersuite_to_use){
	/* return 1 if key_exchange has to be done, 0 otherwise */

	if( (!strcmp(ciphersuite_to_use, TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_DSS_WITH_AES_128_CBC_SHA)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_RSA_WITH_AES_128_CBC_SHA)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_DSS_WITH_AES_256_CBC_SHA)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_RSA_WITH_AES_256_CBC_SHA)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_DSS_WITH_AES_128_CBC_SHA256)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_DSS_WITH_AES_256_CBC_SHA256)) ||
		(!strcmp(ciphersuite_to_use, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)) ){
		return 1;
	}
	else return 0;
}



int server_hello (FILE* log_server, char * ciphersuite_to_use, char * random_from_client){

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
	chose_best_ciphersuite (received_message, ciphersuite_to_use);
	// Generate Random part
	char * random_part = calloc(32, sizeof(char));
	random_part = gen_rdm_bytestream_server(32);
	// Send Hello Server to the Client
	channel = fopen(link_channel,"w");
	send_message (channel, 4, TLS_HANDSHAKE, TLS_SERVERHELLO, random_part, ciphersuite_to_use);
	// Save it in log_server
	send_message (log_server, 5, sending, TLS_HANDSHAKE, TLS_SERVERHELLO, random_part, ciphersuite_to_use);
	fprintf(log_server, "\n\n");
	fclose(channel);
	free(received_message);
	return 1;
}

int send_certificate(FILE* log_server, char * ciphersuite_to_use){
	  
	// Allocate memory to contain the certificate
	char * certificate = calloc(BUF_SIZE,sizeof(char));
	// Read the certificate (yes... 'read_channel' is an abusing of name)
	certificate = get_certificate();
	// Send message to the channel
	FILE* channel = fopen(link_channel,"w");
	send_message (channel, 3, TLS_HANDSHAKE, TLS_SERVERCERTIFICATE, certificate);
	fclose(channel);
	// Save message in log_server
	send_message (log_server, 4, sending, TLS_HANDSHAKE, TLS_SERVERCERTIFICATE, certificate);
	fprintf(log_server, "\n\n");
	free(certificate);
	return 1;
}

int key_exchange(FILE* log_server, char * ciphersuite_to_use){
	return 1;
}

int hello_done(FILE* log_server){

	FILE* channel = fopen(link_channel,"w");
	send_message (channel, 2, TLS_HANDSHAKE, TLS_SERVERHELLODONE);
	fclose(channel);
	send_message (log_server, 3, sending, TLS_HANDSHAKE, TLS_SERVERHELLODONE);
	fprintf(log_server, "\n\n");
	return 1;
}












