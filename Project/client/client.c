#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "client_states.c"


int main(){

	FILE *log_client;
	char ciphersuite_to_use[3];
	char * random_from_server = calloc(32, sizeof(char));

	log_client = fopen("./client/log_client.txt","w");

	int state = 0;
	/* The variable 'state'indicates the state of the client, i.e.
	* state = 0 means: the client is sending through the cannel to the
	*				   server 
	*
	*
	*/
	// TODO add an input command line to make the user able to choose the protocols to use
	
	while(true){
		if (check_semaphore_CLIENT() == true){ // check if the file is exists

			if(state == 0){
				hello_client(log_client);
				printf("Client: hello_client\n"); // to delete
			}
			else if(state == 1){
				receive_hello_server(log_client, ciphersuite_to_use, random_from_server);
				printf("Client: receive_hello_server\n"); // to delete
			}
			else if(state == 2){
				receive_certificate (log_client);
				printf("Client: receive_server_certificate\n"); // to delete
			}
			else if(state == 3){
				printf("Client 3\n"); // to delete
			}
			else if(state == 4){
				printf("Client 4\n"); // to delete
				change_semaphore_CLIENT();
				break;
			}
			state++;
			change_semaphore_CLIENT();
		}
	}
	close_all();
	fclose(log_client);

	return 0;
}
