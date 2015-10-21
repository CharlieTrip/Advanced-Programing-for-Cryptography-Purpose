#include <stdio.h>

int main(void){
	
	int base = 0;
	int esponente = 0;
	char giusto = 0;
	unsigned int i = 0;
	long int risultato = 1;
	float risultatonegativo = 1;

	printf("Esponente intero\n ---.---.---\n");
	
	do{
		printf("\tBase : ");
		
		if ( ! scanf("%d",&base)) {
		
			// Magia nera
			while (getchar()!='\n');
		
			printf("Err : valori interi in input.\n");
			giusto = 1;
		
		}
		
		else {
			
			while (getchar()!='\n');
			giusto = 0;
		}

	}while(giusto);
	

	
	giusto = 0;

	do{
		printf("\tEsponente : ");

		if ( ! scanf("%d",&esponente)) {
		
			// Magia bianca
			while (getchar()!='\n');
		
			printf("Err : valori interi in input.\n");
			giusto = 1;
		
		}
		else {
			
			while (getchar()!='\n');
			giusto = 0;
		}

	}while(giusto);



	if(esponente>=0){
		i = 0;
		for(;i<esponente;i++)
			risultato *= base;
		printf("%d ** %d = %ld\n",base,esponente,risultato);
	}
	else{
		i = 0;
		for(;i<(-esponente);i++)
			risultatonegativo /= base;	
		printf("%d ** %d = %f\n",base,esponente,risultatonegativo);
	}

	return 0;
}