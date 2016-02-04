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
	send_message (channel, 5, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, hexrandom, TLS_RSA_WITH_SHA256);
	// Save it in log_client
	send_message (log_client, 6, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, hexrandom, TLS_RSA_WITH_SHA256);
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
	if ( !(atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA256)) ){
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



int change_cipher_spec(FILE* log_client){

	FILE* channel = fopen (link_channel,"w");

	// Send ChangeCipherSuite to the Server
	send_message (channel, 3, TLS_VERSION, TLS_HANDSHAKE, TLS_CHANGECIPHERSPEC);
	send_message (log_client, 4, sending , TLS_VERSION, TLS_HANDSHAKE, TLS_CHANGECIPHERSPEC);
	fprintf(log_client,  "\n\n");
	fclose (channel);
	return 1;
}

int client_finished(FILE* log_client, char * master_secret, char * ciphersuite_to_use){

	int len_sha;
	FILE* channel = fopen (link_channel,"w");
	//if(true) { // condizione se si sta usando lo sha2
		len_sha = 32;
		unsigned char * hash_client_log = calloc (len_sha*2 , sizeof(char));
		HMAC_SHA2_file(log_client, (unsigned char *) master_secret, (int)strlen(master_secret), (unsigned char *) "", (unsigned char *) hash_client_log);
	//}
	// Send finish
	send_message (channel, 4, TLS_VERSION, TLS_HANDSHAKE , TLS_FINISHED , hash_client_log);
	send_message (log_client, 5, sending, TLS_VERSION, TLS_HANDSHAKE , TLS_FINISHED , hash_client_log);
	fprintf(log_client,  "\n\n");
	fclose(channel);
	return 1;
}

int receive_change_cipher_spec(FILE * log_client){

	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	// Read data from channel
	read_channel (channel, received_message);
	fclose(channel);
	// Save it in log_server
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	return 1;
}

int receive_server_finished(FILE* log_client, unsigned char * master_secret, char * ciphersuite_to_use){
	int len_sha;
	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	// Read data from channel
	read_channel (channel, received_message);
	fclose(channel);
	//if(true) { // condizione se si sta usando lo sha2
		len_sha = 32;
		// Get the hash of the client_log
		unsigned char * hash_server_log;
		unsigned char * hash_client_log = calloc(len_sha*2, sizeof(char));
		hash_server_log = (unsigned char*) get_nth_block(received_message, 4);
		// Fai l'hash del  server_log
		fclose(log_client); log_client = fopen("./client/log_client.txt","r");
		HMAC_SHA2_file(log_client, (unsigned char *) master_secret, (int)strlen((char*) master_secret), (unsigned char *) "", (unsigned char *) hash_client_log);
		fclose(log_client); log_client = fopen("./client/log_client.txt","a");
		//}
	if(strcmp( (char*) hash_client_log, (char*) hash_server_log)){
		// TODO handle herror
		free(received_message); free(hash_client_log);
		return 0;
	}
	else{
		send_message (log_client, 2, receiving, received_message);
		fprintf(log_client, "\n\n");
		free(received_message); free(hash_client_log);
		return 1;
	}
}














