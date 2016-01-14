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

    open_semaphore_to_CLIENT();

	int state = 0;
	/* The variable 'state'indicates the state of the server, i.e.
	* state = 0 means: the server read what the client has sent, choose the best ciphersuite between the disponible ones,
	*				   send the message Hello ecc... to the client
	*
	*
	*/

	while(true){
		if (check_semaphore_SERVER() == true){  // check if the file is exists

			if(state == 0){
				server_states_0(log_server, ciphersuite_to_use,random_from_client);
				change_semaphore_SERVER();
				state++;
				break;
			}
			else if(state == 1){
				break;
			}
			else if(state == 2){
				//
			}
			else if(state == 3){
				//
			}
			else if(state == 4){
				//
			}
			state++;
			//change_semaphore_SERVER();
			
		}
	}

	//close_all();
	fclose(log_server);
	remove("./common/channel.txt");

return 0;
}


