#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(){

	    // Control before to start
    if (access("./semaphore/ok_server.txt", F_OK) != -1)
        remove("./semaphore/ok_server.txt");
    if (access("./semaphore/ok_client.txt", F_OK) != -1)
        remove("./semaphore/ok_client.txt");
    return 1;
}