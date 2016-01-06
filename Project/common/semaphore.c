// 
// [WIP]
// 
// Functions for the concurrency on the channel

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>

bool check_semaphore_SERVER(){
	/* the server check if its connection is open */
	if (access("ok_server.txt", F_OK) != -1)
		return true;
	else
		return false;
}

void change_semaphore_SERVER(){
	/* the server close its connection 
	and open the connection for the client */ 
	remove("ok_server.txt");
	fopen("ok_client.txt","w");
}


bool check_semaphore_CLIENT(){
	/* the client check if its connection is open */
	if (access("ok_client.txt", F_OK) != -1)
		return true;
	else
		return false;
}

void change_semaphore_CLIENT(){
	/* the client close its connection 
	and open the connection for the server */ 
	remove("ok_client.txt");
	fopen("ok_server.txt","w");
}

void close_all(){
    /* close all the connection */
    remove("ok_client.txt");
    remove("ok_server.txt");
}