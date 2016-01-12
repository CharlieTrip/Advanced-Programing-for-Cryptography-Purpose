#include <stdio.h>
#include <stdlib.h>
#include "../common/constants.h"
#include "../common/file.c"

//TODO handle error cases,

const char receiving[13] = "**client** :";
const char sending[13] = "**server** :"; 

int server_states_1 (FILE* log_server, FILE* channel){

	/* for the moment we suppose the client can use all 4 types of protocol */

	//unsigned char * random_part = calloc(32, sizeof(char));
	//random_part = gen_rdm_bytestream(32);

	char * received_message = calloc(BUF_SIZE,sizeof(char));

	// Read data from channel ad save it in log_server
	read_channel(channel, received_message);
	send_message(log_server, 2, receiving, received_message);

	free(received_message);

	return 0;

}