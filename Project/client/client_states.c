#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"


//TODO handle error cases, 

const char sending[13] = "**client** :";
const char receiving[13] = "**server** :"; 




int client_states_1 (FILE* log_client, FILE* channel){

	/* for the moment we suppose the client can use all 4 types of protocol */

	unsigned char * random_part = calloc(32, sizeof(char));
	random_part = gen_rdm_bytestream(32);


	// the number 8 indicates number of blocks
	send_message (channel, 8, "8", TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, TLS_DH_RSA_SHA1, TLS_DH_RSA_SHA2, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);
	send_message (log_client, 9, sending, "8", TLS_HANDSHAKE, TLS_CLIENTHELLO, random_part, TLS_DH_RSA_SHA1, TLS_DH_RSA_SHA2, TLS_RSA_RSA_SHA1, TLS_RSA_RSA_SHA2);

	return 0;

}