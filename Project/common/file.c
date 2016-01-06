
 /* following code assumes all file operations succeed. In practice,
 * return codes from open, close, fstat, mmap, munmap all need to be
 * checked for error. It returns 0 if the line is read,  -1 in case
 of error.

it returns the content of a line, example: if a line is
'05 +server+: testprova' it returns just 'testprova'
*/
 
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE ( 2048 )
 

int get_nth_line( FILE *f, int line_no, char *content_of_line)
{
    char   buf[ BUF_SIZE ];
    char *line = malloc( BUF_SIZE );
    size_t curr_alloc = BUF_SIZE, curr_ofs = 0;
    int    in_line    = line_no == 1;
    size_t bytes_read;
 
    /* Illegal to ask for a line before the first one. */
    if ( line_no < 1 )
        return -1;
 
    /* Handle out-of-memory by returning NULL */
    if ( !line )
        return -1;
 
    /* Scan the file looking for newlines */
    while ( line_no && 
            ( bytes_read = fread( buf, 1, BUF_SIZE, f ) ) > 0 )
    {
        int i;
 
        for ( i = 0 ; i < bytes_read ; i++ )
        {
            if ( in_line )
            {
                if ( curr_ofs >= curr_alloc )
                {
                    curr_alloc <<= 1;
                    line = realloc( line, curr_alloc );
 
                    if ( !line )    /* out of memory? */
                        return -1;
                }
                line[ curr_ofs++ ] = buf[i];
            }
 
            if ( buf[i] == '\n' )
            {
                line_no--;
 
                if ( line_no == 1 )
                    in_line = 1;
 
                if ( line_no == 0 )
                    break;
            }
        }
    }
 
    /* Didn't find the line? */
    if ( line_no != 0 ) 
    {
        free( line );
        return -1;
    }
 
    /* Resize allocated buffer to what's exactly needed by the string 
       and the terminating NUL character.  Note that this code *keeps*
       the terminating newline as part of the string. 
     */
    line = realloc( line, curr_ofs + 1 );
 
    if ( !line ) /* out of memory? */
        return -1;
 
    /* Add the terminating NUL. */
    line[ curr_ofs ] = '\0';

    for(int i = 0; i<20; i++){
    	if(line[i] == ':'){
    		strcpy(content_of_line,line+i+2);
    		break;
    	}
    }
    return 0;
    free(line);
}
