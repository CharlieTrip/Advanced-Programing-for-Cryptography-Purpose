
#include "server_cases.h"


int hello_server (FILE* log_server, char * ciphersuites_to_use, char * random_from_client, char * random_from_server){

	/* for the moment we suppose the client can use all 4 types of protocol */

	unsigned char * hexRandomClient;
	unsigned char * hexRandomServer = calloc(2*RANDOM_DIM_HELLO+1, sizeof(unsigned char));
	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	// Read data from channel
	read_channel (channel, received_message);
	fclose(channel);
	// Handle errors
	if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
		closeConversation(log_server);
	}
	// Save it in log_server
	send_message (log_server, 2, receiving, received_message);
	fprintf(log_server, "\n\n");
	// Get the random from the client which is in position 4
	hexRandomClient = (unsigned char *) get_nth_block(received_message, 4);
	// Convert from hex	
	hexToString((char *) hexRandomClient, random_from_client);
	// Chose the best ciphersuite avilable
	get_block(received_message, 5, ciphersuites_to_use);
	// Generate Random part
	gen_rdm_bytestream(RANDOM_DIM_HELLO, random_from_server, hexRandomServer);
	// Send Hello Server to the Client
	channel = fopen(link_channel,"w");
	send_message (channel, 5, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLO, hexRandomServer, ciphersuites_to_use);
	// Save it in log_server
	send_message (log_server, 6, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLO, hexRandomServer, ciphersuites_to_use);
	fprintf(log_server, "\n\n");
	fclose(channel);
	//free(hexRandomClient);
	free(hexRandomServer);
	free(received_message);
	return 1;
}

int send_certificate(FILE* log_server, char * ciphersuite_to_use){

	char * link_certificate = "./certificate_server/RSA_cert.pem";
	char * certificate = get_certificate(link_certificate);
	
	// Send message to the channel
	FILE* channel = fopen(link_channel,"w");
	send_message (channel, 4, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVER_CERTIFICATE, certificate);
	fclose(channel);
	// Save message in log_server
	send_message (log_server, 5, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVER_CERTIFICATE, certificate);
	fprintf(log_server, "\n\n");
	//free(certificate);
	return 1;
}

int server_key_exchange(FILE* log_server, char * ciphersuite_to_use, char* random_from_client, char* random_from_server, DH * dh){

	if(atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA256) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA384) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA224) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA512)){
		RSA_Key_exchange(log_server, ciphersuite_to_use, random_from_client, random_from_server, dh);
	}

	return 1;
}



int hello_done(FILE* log_server){
    
    
    FILE* channel = fopen(link_channel,"r");
    char * received_message = calloc(BUF_SIZE+1,sizeof(char));
    // Read data from channel
    read_channel (channel, received_message);
    fclose(channel);
    if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
        closeConversation(log_server);
    }
    free(received_message);

	// Send message to the channel
	channel = fopen(link_channel,"w");
	send_message (channel, 3, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLODONE);
	fclose(channel);
	// Save message in log_server
	send_message (log_server, 4, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERHELLODONE);
	fprintf(log_server, "\n\n");
    
	return 1;
}



int receive_exchange_key(FILE * log_server, char * ciphersuite_to_use, unsigned char * master_secret, char * premaster_secret, char * random_from_client, char * random_from_server){

    if(!decrypt_secret_RSA(log_server, premaster_secret)){
        printf("SERVER: decription failed\n");
        return 0;
    }
    
    const EVP_MD * evp_md;
    
    if(atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA224) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA224)){
        evp_md = EVP_sha224();
    }
    else if(atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA256) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA256)){
        evp_md = EVP_sha256();
    }
    else if(atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA384) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA384)){
        evp_md = EVP_sha384();
    }
    else {
        evp_md = EVP_sha512();
    }
    
	if(!compute_master_secret (master_secret, evp_md, random_from_client, random_from_server, premaster_secret, "master secret")){
		printf("SERVER: computing master_secret failed\n");
		return 0;
	}
	return 1;
}


int receive_change_cipher_spec(FILE * log_server){

	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	// Read data from channel
	read_channel (channel, received_message);
	fclose(channel);
	if(!strcmp(received_message, TLS_ERROR_OCCURRED)){
		closeConversation(log_server);
	}
	// Save it in log_server
	send_message (log_server, 2, receiving, received_message);
	fprintf(log_server, "\n\n");
	return 1;
}

int change_cipher_spec(FILE * log_server, unsigned char * master_secret, char * ciphersuite_to_use){

	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	// Read data from channel
	read_channel (channel, received_message);
	fclose(channel);
	if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
		closeConversation(log_server);
	}
    // Get the hash of the client_log
    unsigned char * hash_client_log = calloc(24, sizeof(unsigned char));
    unsigned char * hash_server_log = calloc(24, sizeof(unsigned char));
    get_block(received_message, 4, (char*) hash_client_log);
    
    const EVP_MD * evp_md;
    
    if(atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA224) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA224)){
        evp_md = EVP_sha224();
    }
    else if(atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA256) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA256)){
        evp_md = EVP_sha256();
    }
    else if(atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA384) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA384)){
        evp_md = EVP_sha384();
    }
    else {
        evp_md = EVP_sha512();
    }
    
    fclose(log_server); log_server = fopen("./log/log_server.txt","r");
    // Compute the hash of the log
    compute_hash_log(log_server, evp_md, (unsigned char *) master_secret, 48, hash_server_log);
    fclose(log_server); log_server = fopen("./log/log_server.txt","a");
    // Compare the two hash
	if(strcmp( (char*) hash_client_log, (char*) hash_server_log)){
		printf("SERVER: comparing hash log failed\n");
		free(received_message); free(hash_server_log);
		return 0;
	}
	else{
		// Save it in log_server
		send_message (log_server, 2, receiving, received_message);
		fprintf(log_server, "\n\n");
		free(received_message); free(hash_server_log);

		FILE* channel = fopen (link_channel,"w");

		// Send ChangeCipherSuite to the Server
		send_message (channel, 3, TLS_VERSION, TLS_HANDSHAKE, TLS_CHANGECIPHERSPEC);
		send_message (log_server, 4, sending , TLS_VERSION, TLS_HANDSHAKE, TLS_CHANGECIPHERSPEC);
		fprintf(log_server,  "\n\n");
		fclose (channel);
		return 1;
	}
}

int server_finished(FILE* log_server, char * master_secret, char * ciphersuite_to_use){
    
	FILE* channel = fopen (link_channel,"w");
    unsigned char * hash_server_log = calloc (24 , sizeof(unsigned char));

    const EVP_MD * evp_md;
    
    if(atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA224) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA224)){
        evp_md = EVP_sha224();
    }
    else if(atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA256) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA256)){
        evp_md = EVP_sha256();
    }
    else if(atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA384) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA384)){
        evp_md = EVP_sha384();
    }
    else {
        evp_md = EVP_sha512();
    }
    
    
     // Compute the hash of the log
    fclose(log_server); log_server = fopen("./log/log_server.txt","r");
    compute_hash_log(log_server, evp_md, (unsigned char *) master_secret, 48, hash_server_log);
    fclose(log_server); log_server = fopen("./log/log_server.txt","a");
	// Send finish
	send_message (channel, 4, TLS_VERSION, TLS_HANDSHAKE , TLS_FINISHED , hash_server_log);
	send_message (log_server, 5, sending, TLS_VERSION, TLS_HANDSHAKE , TLS_FINISHED , hash_server_log);
	fclose(channel);
	return 1;
}





