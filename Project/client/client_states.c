
#include "client_states.h"


int hello_client (FILE* log_client, char * random_from_client, char * ciphersuite_to_use){

	/* for the moment we suppose the client can't use all 4 types of ciphersuite */

	FILE* channel = fopen (link_channel,"w");
	unsigned char * hexrandom = calloc(2*RANDOM_DIM_HELLO+1, sizeof(unsigned char));
	// Generate Random part
	gen_rdm_bytestream (RANDOM_DIM_HELLO, random_from_client, hexrandom);
    
	// Send Hello Client to the Server
	send_message (channel, 5, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, hexrandom, ciphersuite_to_use);
	// Save it in log_client
	send_message (log_client, 6, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTHELLO, hexrandom, ciphersuite_to_use);
	fprintf(log_client, "\n\n");
	fclose (channel);
	free(hexrandom);
	return 1;
}


int receive_hello_server (FILE* log_client, char * random_from_server){

	unsigned char * hexRandomServer;
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
		closeConversation(log_client);
	}
	// Save it in log_client
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	// Get the random from the client
	hexRandomServer = (unsigned char*) get_nth_block(received_message, 4);
	hexToString((char*) hexRandomServer, random_from_server);
	//free(hexRandomServer);
	return 1;
}


int receive_certificate (FILE* log_client, char * ciphersuite_to_use){

	char * certificate;
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
		closeConversation(log_client);
	}
	// Save it in log_client
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	// Open a .pem file to write the certificate
	FILE *cert_file = fopen(RSA_link_certificate, "w");
	// Extract the certificate from the received message and write it in a .pem file
	certificate = get_nth_block(received_message,CERTIFICATE_POSITION);
	PEM_write_X509(cert_file, string_to_X509(certificate));
 	free(received_message);
 	fclose(cert_file);
    // Write the public key in a .PEM file
    get_pubkey(RSA_link_public_key, RSA_link_certificate);
	return 1;
}


int receiving_key_exchange(FILE * log_client, char * ciphersuite_to_use, char * random_from_client, char * random_from_server, DH * dh){
    
    // create struct RSA
    RSA *rsa = NULL;
    FILE *fp;
    
    if((fp= fopen(RSA_link_public_key, "r")) != NULL){
        rsa=PEM_read_RSA_PUBKEY(fp,NULL,NULL,NULL);
        if(rsa==NULL){
            printf("CLIENT: Unable to open RSA pubblic key");
            return 0;
        }
    }
    fclose(fp);
    
    char * stringsignature = calloc(256, sizeof(char));
    unsigned char * hash = calloc(32, sizeof(unsigned char));
    
    //Receive message
    char * received_message = calloc(BUF_SIZE+1,sizeof(char));
    FILE* channel = fopen (link_channel,"r");
    // Read data from channel
    read_channel (channel, received_message);
    fclose (channel);
    //Save it in log
    send_message (log_client, 2, receiving, received_message);
    fprintf(log_client, "\n\n");
    
    // get prime number, generator, pubkey
    BIGNUM *bnprime = BN_new();
    BIGNUM *bngenerator = BN_new();
    BIGNUM *bnpubkey = BN_new();
    char * blockprime = calloc(128+1,sizeof(char));
    char * blockgenerator = calloc(2+1,sizeof(char));
    char * blockpubkey = calloc(128+1,sizeof(char));
    get_block(received_message, 5, blockprime);
    get_block(received_message, 6, blockgenerator);
    get_block(received_message, 7, blockpubkey);
    BN_hex2bn( &bnprime, blockprime);
    BN_hex2bn( &bngenerator, blockgenerator);
    BN_hex2bn( &bnpubkey, blockpubkey);
    dh->p = bnprime;
    dh->g = bngenerator;
    dh->pub_key = bnpubkey;
    
    // converts into char
    char * prime = calloc(BN_num_bytes(dh->p)+1, sizeof(char));
    char * generator = calloc(BN_num_bytes(dh->g)+1, sizeof(char));
    char * pubkey = calloc(BN_num_bytes(bnpubkey)+1, sizeof(char));
    
    hexToString(blockprime, prime);
    hexToString(blockgenerator, generator);
    hexToString(blockpubkey, pubkey);

    //free(blockprime); free(blockgenerator); free(blockpubkey);
    // Get the signature
    char * signature = get_nth_block(received_message,8);

    // Transform signature into char
    hexToString( signature, stringsignature);
    int len_message = 64+64+1;
    
    char * message = calloc(len_message+1,sizeof(char));
    strncpy(message, random_from_client,32);
    strncat(message, random_from_server,32);
    strncat(message, prime, 32);
    strncat(message, generator,1);
    strncat(message, pubkey,32);
    
    // Hash message
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, len_message);
    SHA256_Final(hash, &sha256);
    
    // Veirfy the signature
    if(!RSA_verify(NID_sha256, (const unsigned char *) hash, 32, (const unsigned char *) stringsignature, 256, rsa)){
        RSA_free(rsa);
        printf("CLIENT: verification of the signature failed\n");
        return 0;
    }
    RSA_free(rsa);
    return 1;
}



int exchange_key(FILE* log_client, char * ciphersuite_to_use, unsigned char * master_secret, char * premaster_secret, char * random_from_client, char * random_from_server, DH * dh){

	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
		closeConversation(log_client);
	}
	// Write to log_client the received message
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	free(received_message);
    // compute and exchange premaster_secret
	if ( atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA256) ||
        atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA384) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA224) ||
        atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA512)){
		encrypt_secret_RSA(log_client, premaster_secret);
	}
	else if (atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA256) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA384) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA224) || atoi(ciphersuite_to_use) == atoi(TLS_DHE_RSA_WITH_SHA512)){
		encrypt_secret_DH(log_client, premaster_secret, received_message, dh);
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
    else{
        evp_md = EVP_sha512();
    }
    
	if(!compute_master_secret (master_secret, evp_md, random_from_client, random_from_server, premaster_secret, "master secret")){
		printf("CLIENT: computing master_secret failed\n");
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

	FILE* channel = fopen (link_channel,"w");

    unsigned char * hash_client_log = calloc (24 , sizeof(unsigned char));
    fclose(log_client); log_client = fopen("./log/log_client.txt","r");
    // Compute hash of the log
    
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

    
    compute_hash_log(log_client, evp_md, (unsigned char *) master_secret,(int) strlen((const char *)master_secret), hash_client_log);
    fclose(log_client); log_client = fopen("./log/log_client.txt","a");
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
	if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
		closeConversation(log_client);
	}
	// Save it in log_server
	send_message (log_client, 2, receiving, received_message);
	fprintf(log_client, "\n\n");
	return 1;
}

int receive_server_finished(FILE* log_client, unsigned char * master_secret, char * ciphersuite_to_use){

	FILE* channel = fopen(link_channel,"r");
	char * received_message = calloc(BUF_SIZE,sizeof(char));
	// Read data from channel
	read_channel (channel, received_message);
	fclose(channel);
    // Control errors
	if(!strcmp(received_message,TLS_ERROR_OCCURRED)){
		closeConversation(log_client);
	}
    // Get the hash of the client_log
    unsigned char * hash_server_log = calloc(24, sizeof(char));
    unsigned char * hash_client_log = calloc(24, sizeof(char));
    get_block(received_message, 4, (char*) hash_server_log);
    
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
    fclose(log_client); log_client = fopen("./log/log_client.txt","r");
    compute_hash_log(log_client, evp_md, (unsigned char *) master_secret, 48, hash_client_log);
    fclose(log_client); log_client = fopen("./log/log_client.txt","a");
	// Compare the two hash
    if(strcmp( (char*) hash_client_log, (char*) hash_server_log)){
		free(received_message); free(hash_client_log);
        printf("CLIENT: comparing hash log failed\n");
        // Save message in log
        send_message (log_client, 2, receiving, received_message);
        free(received_message); free(hash_client_log);
		return 0;
	}
	else{
        // Save message in log
        send_message (log_client, 2, receiving, received_message);
        free(received_message); free(hash_client_log);
		return 1;
	}
}














