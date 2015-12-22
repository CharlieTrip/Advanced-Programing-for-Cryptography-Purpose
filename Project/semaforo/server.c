#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* Ci sono due file di testo che vengono usati: uno è canale.txt 
 	che non è altro il file in cui vengono scritte le varie "cose",
 	l'altro è semaforo.txt: questi file viene creato prima e 
 	cancellato dopo ogni comunicazione. Dunque il server (per esempio)
 	verifica prima se il file è presente: se lo è allora non fa nulla,
 	se non lo è allora può scrivere poi aspetta 1 secondo (per dare il
 	tempo al client di verificare e scrivere. Stessa cosa fa il client
*/

int main(){

	int count = 0;

	time_t endwait;
    time_t start = time(NULL);
    time_t seconds = 10;
    endwait = start + seconds;



    FILE *canale;

while(start < endwait){


	start = time(NULL);

	if (access("semaforo.txt", F_OK) != -1){  //verifico se il file semaforo.txt è presente	
	}
	else{ // se non è presente faccio i vari comandi
		fopen("semaforo.txt","w");
		canale = fopen("canale.txt","a");
		fprintf(canale, "server %d \n",count++);
		fclose(canale);
		remove("semaforo.txt");
		sleep(1);
	}
}



return 0;
}