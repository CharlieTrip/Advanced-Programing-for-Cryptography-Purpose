
#include "server_cases.h"

const char receiving[] = "**client** :";
const char sending[] = "**server** :"; 
const char * link_RSA_prvkey = "./certificate_server/RSA_privkey.pem";


int RSA_Key_exchange(FILE* log_server, char * ciphersuite_to_use, char* random_from_client, char* random_from_server, DH * dh){

	// create struct RSA
    RSA *rsa = NULL;
    FILE *fp;
    
    if((fp= fopen(link_RSA_prvkey, "r")) != NULL){
        rsa=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
        if(rsa==NULL){
            printf("SERVER: unable to open RSA private key\n");
            return 0;
        }
    }
    fclose(fp);
    
	// Initializate struct DH and generate parameters and keys
	DH_generate_parameters_ex(dh, 512, DH_GENERATOR_2, 0);
	DH_generate_key(dh);
	char * prime = BN_bn2hex(dh->p);
	char * generator = BN_bn2hex(dh->g);
	char * pubkey = BN_bn2hex(dh->pub_key);
    
    // converts into char
    char * char_prime = calloc(BN_num_bytes(dh->p)+1, sizeof(char));
    char * char_generator = calloc(BN_num_bytes(dh->g)+1, sizeof(char));
    char * char_pubkey = calloc(BN_num_bytes(dh->pub_key)+1, sizeof(char));
    
    hexToString(prime, char_prime);
    hexToString(generator, char_generator);
    hexToString(pubkey, char_pubkey);

    // Create the message
    int len_message = 64+64+1;
	char * message = calloc(len_message+1,sizeof(char));
	strncpy(message, random_from_client,32);
    strncat(message, random_from_server,32);
    strncat(message, char_prime, 32);
    strncat(message, char_generator, 1);
    strncat(message, char_pubkey, 32);
    
    //Signature
	unsigned char * signature = calloc(RSA_size(rsa),sizeof(unsigned char));
	unsigned int len_signature;
    
    // Hash message
    unsigned char * hash = calloc(32, sizeof(unsigned char));
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, len_message);
    SHA256_Final(hash, &sha256);
    
    // Compute signature
	RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &len_signature, rsa);
    
    //Transform into hex
    unsigned char * hexsignature = calloc(256*2, sizeof(unsigned char));
    stringToHex((char*) signature , 256, (char*) hexsignature);
    
	// Send message to the channel
	FILE * channel = fopen(link_channel,"w");
	send_message (channel, 8, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERKEYEXCHANGE, TLS_SIGN_RSA_SHA256, prime, generator, pubkey, hexsignature);
	fclose(channel);

	// Save message in log_server
	send_message (log_server, 9, sending, TLS_VERSION, TLS_HANDSHAKE, TLS_SERVERKEYEXCHANGE, TLS_SIGN_RSA_SHA256, prime, generator, pubkey, hexsignature);
    fprintf(log_server, "\n\n");
    free(signature); free(hexsignature);
  	//RSA_free(rsa);
	return 1;
}



int decrypt_secret_RSA(FILE * log_server, char * premaster_secret){

	char * converted_enc_pm_secret = calloc(BUF_SIZE,sizeof(char));
	char * encrypted_pm_secret;
	char * received_message = calloc(BUF_SIZE+1,sizeof(char));
	FILE* channel = fopen (link_channel,"r");
	// Read data from channel
	read_channel (channel, received_message);
	fclose (channel);
	// Save message in log_server
	fprintf(log_server, "%s\t", receiving);
	for(int i = 0; i<(512+3+6); i++){
		fprintf(log_server, "%c", received_message[i]);
	}
	fprintf(log_server, "\n\n");
	// extact the encrypted premaster_secret
	encrypted_pm_secret = get_nth_block(received_message,PREMAS_SECRET_POSITION);
	
	hexToString(encrypted_pm_secret, converted_enc_pm_secret);
	
	// Decrypt
	if(-1 == TLS_RSA_private_decrypt((unsigned char *) converted_enc_pm_secret, 256, link_RSA_prvkey, (unsigned char *) premaster_secret)){
		printf("SERVER: Private Decrypt failed ");
        return 0;
	}
	return 1;
}


int check_input(char * argv[]){

    if (!strcmp(argv[1], "-DHE_SHA256") || !strcmp(argv[1], "-RSA_SHA256") || !strcmp(argv[1], "-DHE_SHA384") || !strcmp(argv[1], "-RSA_SHA384") || !strcmp(argv[1], "-DHE_SHA224") || !strcmp(argv[1], "-RSA_SHA224") || !strcmp(argv[1], "-DHE_SHA512") || !strcmp(argv[1], "-RSA_SHA512")){
            return 1;
           }
    else {
        exit(-1);
        return 0;
    }
}



