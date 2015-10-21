// 7 : 111 ---> n shift a sinistra elimando quelli a sinistra

#include <stdio.h>

int main(void){

	char giusto = 0;
	int numero = 0;
	unsigned risultato = 0;
	unsigned int esponente = 0;
	int i = 0;
	
	printf("Stampa numero in binario\n ---.---.---\n");
	
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
	

	// Trovo l'esponente massimo

	risultato = numero;

	for(; 
		// Divido per 2 e trovo finché non è uguale a 0
		// risultato >> 1 : praticamente
		(risultato/=2) != 0
		; esponente++);


	i = esponente;
	for(; i >= 0;i--){
		printf("%d", ( (numero /(1<<i)) %2) );
	}

	printf("\n");

	return 0;
	
}