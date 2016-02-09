
#include "client_cases.h"

const char sending[] = "**client** :";
const char receiving[] = "**server** :"; 
const char * RSA_link_public_key = "./certificate_client/RSA_pubkey.pem";
const char * RSA_link_certificate = "./certificate_client/RSA_cert.pem";


int encrypt_secret_DH(FILE* log_client, char * premaster_secret, char * received_message, DH * dh){
    
    char * encrypted_secret = calloc(BUF_SIZE+1,sizeof(char));
    unsigned char * key = calloc(DH_size(dh), sizeof(unsigned char));
    
    BIGNUM * server_py = dh->pub_key;
    
    //BN_free(dh->pub_key);
    dh->pub_key = BN_new();
    DH_generate_key(dh);
    
    if(DH_compute_key(key, server_py, dh) == -1){
        printf("CLIENT: failed while computing premaster secret");
        return 0;
    }
    
    strncpy(premaster_secret, (const char*) key, 48);
    
    // encrypt all with public key RSA sent by the server
    if(-1 == TLS_RSA_public_encrypt((unsigned char *) premaster_secret, (int) strlen(premaster_secret), RSA_link_public_key, encrypted_secret)){
        printf("CLIENT: Public Encrypt failed ");
        return 0;
    }
    
    FILE* channel = fopen (link_channel,"w");
    // Send encrypted premaster_secret to the Server
    send_message (channel, 3, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTKEYEXCHANGE);
    fprintf(channel, "\t");
    // Save it in log_client
    send_message (log_client, 4, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTKEYEXCHANGE);
    fprintf(log_client, "\t");
    // I need to send the encryption byteXbythe since there can be also \0 char
    for(int i = 0; i<256; i++){
        fprintf(log_client, "%02x",(unsigned char) encrypted_secret[i]);
        fprintf(channel, "%02x",(unsigned char) encrypted_secret[i]);
    }
    fprintf(log_client, "\n\n");
    fclose (channel);
    free(encrypted_secret);

	return 1;
}



int encrypt_secret_RSA(FILE* log_client, char * premaster_secret){
// Allocating memory
	char * random_stream = calloc(RANDOM_DIM_KEY_EXCHANGE+1,sizeof(char));
	char * encrypted_secret = calloc(BUF_SIZE+1,sizeof(char));
	// get random part of the premaster_secret
	gen_rdm_bytestream(RANDOM_DIM_KEY_EXCHANGE, random_stream, NULL);
	// copy TLS version to the head of the premaster_secret
	strcpy(premaster_secret,TLS_VERSION);
	// add the random part previously obtained to the premaster_secret
	strcat(premaster_secret,random_stream);
	// deallocating memory
	free(random_stream);
	// encrypt all with public key RSA sent by the server
	if(-1 == TLS_RSA_public_encrypt((unsigned char *) premaster_secret, (int) strlen(premaster_secret), RSA_link_public_key, encrypted_secret)){
	    printf("CLIENT: Public Encrypt failed ");
	    return 0;
	}
	
	FILE* channel = fopen (link_channel,"w");
	// Send encrypted premaster_secret to the Server
	send_message (channel, 3, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTKEYEXCHANGE);
	fprintf(channel, "\t");
	// Save it in log_client
	send_message (log_client, 4, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_CLIENTKEYEXCHANGE);
	fprintf(log_client, "\t");
	// I need to send the encryption byteXbythe since there can be also \0 char
	for(int i = 0; i<256; i++){
		fprintf(log_client, "%02x",(unsigned char) encrypted_secret[i]);
		fprintf(channel, "%02x",(unsigned char) encrypted_secret[i]);
	}
	fprintf(log_client, "\n\n");		
	fclose (channel);
	free(encrypted_secret);
	return 1;
}


char * check_input(char * argv[]){

	char * ciphersuite = NULL;
    
	if (!strcmp(argv[1], "-DHE_SHA256")){
		ciphersuite = (char *) TLS_DHE_RSA_WITH_SHA256;
	}
	else if (!strcmp(argv[1], "-RSA_SHA256")){
		ciphersuite = (char *) TLS_RSA_WITH_SHA256;
	}
    else if (!strcmp(argv[1], "-DHE_SHA384")){
        ciphersuite = (char *) TLS_DHE_RSA_WITH_SHA384;
    }
    else if (!strcmp(argv[1], "-RSA_SHA384")){
        ciphersuite = (char *) TLS_RSA_WITH_SHA384;
    }
    else if (!strcmp(argv[1], "-DHE_SHA224")){
        ciphersuite = (char *) TLS_DHE_RSA_WITH_SHA224;
    }
    else if (!strcmp(argv[1], "-RSA_SHA224")){
        ciphersuite = (char *) TLS_RSA_WITH_SHA224;
    }
    else if (!strcmp(argv[1], "-DHE_SHA512")){
        ciphersuite = (char *) TLS_DHE_RSA_WITH_SHA512;
    }
    else if (!strcmp(argv[1], "-RSA_SHA512")){
        ciphersuite = (char *) TLS_RSA_WITH_SHA512;
    }
    else if (!strcmp(argv[1], "-i")){
        print_file("./mish/info.txt");
        exit(-1);
    }
    else {
        print_file("./mish/usage.txt");
        exit(-1);
    }
    return ciphersuite;
}























