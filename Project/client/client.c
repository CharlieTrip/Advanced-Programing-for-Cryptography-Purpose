#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "client_states.c"


int main(){

	FILE *channel;
	FILE *log_client;

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
			channel = fopen("./common/channel.txt","w+");	
			if (channel != NULL){
				if(state == 0){
					client_states_1(log_client, channel);
					state++;
					fclose(channel);
					change_semaphore_CLIENT();
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

		/*	fclose(channel);
			change_semaphore_CLIENT();
			*/
			}
		}
	}

	fclose(log_client);

	return 0;
}








