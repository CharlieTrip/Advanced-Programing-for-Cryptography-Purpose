#include <stdio.h>
#include <stdlib.h>
#include "client_cases.c"


//TODO handle error cases, 

void hello_client (FILE* log_client, char * random_from_client){

	/* for the moment we suppose the client can't use all 4 types of ciphersuite */

	FILE* channel = fopen (link_channel,"w");
	unsigned char * hexrandom = calloc(2*RANDOM_DIM_HELLO+1, sizeof(char));
	// Generate Random part
	gen_rdm_bytestream (RANDOM_DIM_HELLO, random_from_client, hexrandom);
	// Send Hello Client to the Server
	send_message (channel, 6, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, hexrandom, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);
	// Save it in log_client
	send_message (log_client, 7, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, hexrandom, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);
	fprintf(log_client, "\n\n");
	fclose (channel);
	free(hexrandom);
}


void receive_hello_server (FILE* log_client, char * ciphersuite_to_use, char * random_from_server){

	unsigned char * hexRandomServer = calloc(2*RANDOM_DIM_HELLO+1, sizeof(char));
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Save it in log_client
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	// Get the random from the client
	hexRandomServer = (unsigned char*) get_nth_block(received_message, 4);
	hexToString((char*) hexRandomServer, random_from_server);
	// Get the ciphersuite to use (choosed by the server)
	sprintf (ciphersuite_to_use, "%s", get_nth_block(received_message,CIPHERSUITE_TO_USE_POSITION));
	//free(hexRandomServer);
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




int exchange_key(FILE* log_client, char * ciphersuite_to_use, unsigned char * master_secret, char * premaster_secret, char * random_from_client, char * random_from_server){

	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Write to log_client the received message
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	free(received_message);
	if ( !(atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA1) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA2))){
			//DEVO CAPIRE ANCORA BENE COSA FARE CON TLS_DH_RSA
		//
	}
	else 
		encrypt_secret_RSA(log_client, premaster_secret);

	if(!compute_master_secret (master_secret, random_from_client, random_from_server, premaster_secret, "master secret")){
		//printf("CLIENT: ERROR computing master_secret\n");
		return 0;
	}
	return 1;
}





int change_cipher(FILE* log_client, char * secret, int sha){

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
		HMAC_SHA1_file(tmp_log, (unsigned char *) secret, (int)strlen(secret), (unsigned char *) "", (unsigned char *) hashed_log);
	}
	else {
		hashed_log = calloc (64 , sizeof(char));
		HMAC_SHA2_file(tmp_log, (unsigned char *) secret, (int)strlen(secret), (unsigned char *) "", (unsigned char *) hashed_log);
	}
	// Send finish
	send_message (channel, 4, TLS_VERSION, TLS_HANDSHAKE , TLS_FINISHED , hashed_log);
	send_message (log_client, 5, sending, TLS_VERSION, TLS_HANDSHAKE , TLS_FINISHED , hashed_log);
	fprintf(log_client,  "\n\n");
	
	return 1;
}























