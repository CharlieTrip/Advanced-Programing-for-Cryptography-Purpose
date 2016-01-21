
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "server_states.c"



int main(){

	FILE *log_server;
	char ciphersuite_to_use[3];
	char * random_from_client = calloc(32, sizeof(char));

	log_server = fopen("./server/log_server.txt","w");
	char * state = calloc(50,sizeof(char));
	strcpy(state, "hello_request");

	while(true){
		if (check_semaphore_SERVER() == true){  // check if the file is exists
			if (!strcmp(state, "hello_request")){
				hello_request(log_server);
				printf("SERVER: hello_request\n"); // to delete
				strcpy(state,"server_hello");
				change_semaphore_SERVER();
			}
			else if(!strcmp(state, "server_hello")){
				if(server_hello(log_server, ciphersuite_to_use,random_from_client)){
					printf("SERVER: server_hello\n"); // to delete
					strcpy(state,"sending_server");
					change_semaphore_SERVER();
				}
			}
			else if(!strcmp(state, "sending_server")){
				if(send_certificate(log_server,ciphersuite_to_use)){
					printf("SERVER: sent_certificate\n"); // to delete
					change_semaphore_SERVER();
					break;
				}
			}
		}
	}

	free(state);
	close_all();
	fclose(log_server);

	return 0;
}









