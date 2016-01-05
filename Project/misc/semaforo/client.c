#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* Ci sono due file di testo che vengono usati: uno è canale.txt 
 	che non è altro il file in cui vengono scritte le varie "cose",
 	l'altro è semaforo.txt: questi file viene creato prima e 
 	cancellato dopo ogni comunicazione. Dunque il server (per esempio)
 	verifica prima se il file è presente: se lo è allora non fa nulla,
 	se non lo è allora può scrivere. Stessa cosa fa il client
*/

int main(){

	int count = 0;

    FILE *canale; 
    /*fopen("semaforo.txt","w");
    canale = fopen("canale.txt","w");
    fprintf(canale, "client %d \n",count++);
	fclose(canale);
	sleep(1);
	remove("semaforo.txt");
*/
	fopen("verde_server.txt","w");

while(count < 10){

	if (access("verde_client.txt", F_OK) != -1){  // verifico se il file semaforo.txt è presente
		canale = fopen("canale.txt","a");
		fprintf(canale, "client %d \n",count++);
		printf("client %d \n",count);
		fclose(canale);
		remove("verde_client.txt");
		fopen("verde_server.txt","w");
		sleep(2);
	}
}



return 0;
}