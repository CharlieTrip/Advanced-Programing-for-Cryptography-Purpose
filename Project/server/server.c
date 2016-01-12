#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "server_states.c"



int main(){

    FILE *channel;
	FILE *log_server;

	log_server = fopen("./server/log_server.txt","w");
	channel = fopen("./common/channel.txt","r+");
	fclose(channel);
    open_semaphore_to_CLIENT();

	int state = 0;
	/* The variable 'state'indicates the state of the server, i.e.
	* state = 0 means: the server read what the client has sent and ...
	*				    
	*
	*
	*/

	while(true){
		if (check_semaphore_SERVER() == true){  // check if the file is exists
			channel = fopen("./common/channel.txt","r+");
			if (channel != NULL){
				if(state == 0){
					server_states_1(log_server, channel);
					//state++;
					break;
				}
				if(state == 1){
					//
				}
				if(state == 2){
					//
				}
				if(state == 3){
					//
				}
				if(state == 4){
					//
				}
			}

			fclose(channel);
			//change_semaphore_SERVER();
		}
	}

	close_all();
	fclose(log_server);
	remove("./common/channel.txt");

return 0;
}


