
// Functions for the concurrency on the channel

#include "semaphore.h"

bool check_semaphore_SERVER(){
	/* the server check if its connection is open */
	if (access("./semaphore/ok_server.txt", F_OK) != -1)
		return true;
	else
		return false;
}

void change_semaphore_SERVER(){
	/* the server close its connection 
	and open the connection for the client */
	remove("./semaphore/ok_server.txt");
	fopen("./semaphore/ok_client.txt","w");
}


bool check_semaphore_CLIENT(){
	/* the client check if its connection is open */
	if (access("./semaphore/ok_client.txt", F_OK) != -1)
		return true;
	else
		return false;
}

void change_semaphore_CLIENT(){
	/* the client close its connection 
	and open the connection for the server */ 
	remove("./semaphore/ok_client.txt");
	fopen("./semaphore/ok_server.txt","w");
}

void open_semaphore_to_CLIENT(){
	/* the server open the communication perimissions */
        fopen("./semaphore/ok_client.txt","w");
    
}

void close_all(){
    /* close all the connection */
    remove("./semaphore/ok_client.txt");
    remove("./semaphore/ok_server.txt");
    //remove("./channel.txt");
}
