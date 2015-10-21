// Quadrato, triangolo, rettangolo

#include <stdio.h>

int main(void){

	char giusto = 0;
	int numero = 0;
	int altezza = 0;
	int scelta = 0;
	int i = 0;
	int j = 0;
	int slope = 0;

	
	do{
		printf("Stampa figura\n ---.---.---\n");
		printf("1. Triangolo Equilatero\n");
		printf("2. Quadrato\n");
		printf("3. Rettangolo\n");
		printf("4. Esci\n");

		do{
			printf("\tScelta : ");
			if ( ! scanf("%d",&scelta)) {
				// Magia nera
				while (getchar()!='\n');
				printf("Err : valori interi in input.\n");
				giusto = 1;
			}
			else {
				giusto = 0;
			}
		}while(giusto);

	switch(scelta){
		case 4:
			break;
		case 1:
			do{
				printf("\nLato : ");
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



			slope = 0;

			printf("\n Triangolo \n");

			for(i = 0; i < numero;i++) {
				for(j = 0; j < (numero-1-i); j++)
					printf(" ");
				for(j = 0; j < (i+1); j++)
					printf("* ");
				printf("\n");
			}
			printf("\n");


			break;
		case 2:
			do{
				printf("\nLato : ");
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

			printf("\n Quadrato \n");
			for(i = 0; i < numero;i++) {
				for(j = 0; j < numero; j++)
					printf("*");
				printf("\n");
			}
			printf("\n");



			break;
		case 3:
			do{
				printf("\nBase : ");
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
				printf("\nAltezza : ");
				if ( ! scanf("%d",&altezza)) {
					// Magia nera
					while (getchar()!='\n');
					printf("Err : valori interi in input.\n");
					giusto = 1;
				}
				else {
					if(altezza <0) {
						printf("Err : valori positivi\n");
						giusto = 1;
					}
					else giusto = 0;	
					while (getchar()!='\n');	
				}
			}while(giusto);

			printf("\n Rettangolo \n");
			for(i = 0; i < altezza;i++) {
				for(j = 0; j < numero; j++)
					printf("*");
				printf("\n");
			}
			printf("\n");

			break;

			case 5:
			do{
				printf("\nLato : ");
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



			slope = 0;

			printf("\n TriForce \n");


			for(i = 0; i < (numero);i++) {
				for(j = 0; j < (2*numero-1-i); j++)
					printf(" ");
				for(j = 0; j < (i+1); j++)
					printf("* ");
				printf("\n");
			}
			for(i = 0; i < (numero);i++) {
				for(j = 0; j < (numero-1-i); j++)
					printf(" ");
				for(j = 0; j < (i+1); j++)
					printf("* ");
				for(j = 0; j < (2*numero-2-2*i); j++)
					printf(" ");
				for(j = 0; j < (i+1); j++)
					printf("* ");
				printf("\n");
			}
			printf("\n");


			break;
		}

	}while(scelta != 4);


	
	return 0;
}