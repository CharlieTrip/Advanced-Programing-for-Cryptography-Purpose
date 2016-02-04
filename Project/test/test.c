#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int readfile(FILE *fp)
{
  char ch;
   while( ( ch = fgetc(fp) ) != EOF )
      printf("%c",ch);

   return 0;
}



int main(){


	FILE* file = fopen("log_server.txt","w");
  fprintf(file, "aaaaaaaaasdfghjkwertyuio\n");
  fclose(file);
  file = fopen("log_server.txt","r");
  readfile(file);
	fclose(file);

  return 1;

}
























