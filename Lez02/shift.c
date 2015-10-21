// 7 : 111 ---> n shift a sinistra elimando quelli a sinistra

#include <stdio.h>

int main(void){

	char giusto = 0;
	int numero = 0;
	unsigned int risultato = 0;
	unsigned int esponente = 0;
	unsigned int tmp = 0;
	unsigned int uscita = 0;
	int passi = 0;
	int i = 0;

	
	printf("Shift sinistra e uccidi il massimo esponente\n ---.---.---\n");
	
	do{
		printf("\tNumero : ");
		
		if ( ! scanf("%d",&numero)) {
		
			// Magia nera
			while (getchar()!='\n');
		
			printf("Err : valori interi in input.\n");
			giusto = 1;
		
		}
		
		else {
			if(numero <0) {
				printf("Err : valori positivi\n");
				giusto = 1;
			}
			else giusto = 0;	
			while (getchar()!='\n');
			
		}

	}while(giusto);

	do{
		printf("\tPassi : ");
		
		if ( ! scanf("%d",&passi)) {
		
			// Magia nera
			while (getchar()!='\n');
		
			printf("Err : valori interi in input.\n");
			giusto = 1;
		
		}
		
		else {
			if(passi <0) {
				printf("Err : valori positivi\n");
				giusto = 1;
			}
			else giusto = 0;	
			while (getchar()!='\n');
			
		}

	}while(giusto);
	

	// Trovo l'esponente massimo
	
	risultato = numero;
	
	tmp = risultato;
	
	for(; 
		// Divido per 2 e trovo finché non è uguale a 0
		// risultato >> 1 : praticamente
		(tmp/=2) != 0
		; esponente++);


	for(i = 0; i<passi;i++){

		uscita = uscita*2 + (risultato / (1 << (esponente)));
		
		if ((risultato / (1 << (esponente))) == 1)
			risultato = (risultato * 2) - (1 << (esponente+1));
		else
			risultato = risultato*2; 

		// printf("%d - %d\n",uscita,risultato);

	}
	printf("Shiftato : %d\nUscito : %d\n",risultato,uscita);
	
	return 0;
}