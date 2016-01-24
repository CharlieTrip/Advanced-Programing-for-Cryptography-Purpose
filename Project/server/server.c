
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "server_states.c"



int main(){

	FILE *log_server;
	char ciphersuite_to_use[3];
	char * random_from_client = calloc(RANDOM_DIM_HELLO+1, sizeof(char));
	char * premaster_secret = calloc(BUF_SIZE,sizeof(char));

	log_server = fopen("./server/log_server.txt","w");

    open_semaphore_to_CLIENT();

	int state = 0;
	/* The variable 'state'indicates the state of the server, i.e.
	* state = 0 means: the server read what the client has sent, choose the best ciphersuite between the disponible ones,
	*				   send the message Hello ecc... to the client
	*
	*
	*/

	while(true){
		if (check_semaphore_SERVER() == true){  // checks if the file is exists

			if(state == 0){
				hello_server(log_server, ciphersuite_to_use,random_from_client);
				printf("Server: hello_server\n"); // to delete
			}
			else if(state == 1){
				send_certificate(log_server,ciphersuite_to_use);
				printf("Server: send_certificate\n"); // to delete
			}
			else if(state == 2){
				hello_done(log_server);
				printf("Server: hello_done\n"); // to delete
			}
			else if(state == 3){
				receive_exchange_key(log_server, ciphersuite_to_use, premaster_secret);
				printf("Server: receiving exchange_key\n"); // to delete
			}
			else if(state == 4){
				printf("Server 4\n"); // to delete
				change_semaphore_SERVER();
				break;
			}
			state++;
			change_semaphore_SERVER();
		}
	}

	free(random_from_client);
	//free(premaster_secret);
	close_all();
	fclose(log_server);

return 0;
}
