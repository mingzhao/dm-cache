
#include <stdio.h>



void dump_buffer(char *buffer, int buffer_size)
{
	int c,i;


	for ( c=0;c<buffer_size;c++)
	{
		printf("%.2X ", buffer[c]);

		// put an extra space between every 4 bytes
		if (c % 4 == 3)
		{
			printf(" ");
		}

		// Display 16 bytes per line
		if (c % 16 == 15)
		{
			printf("\n");
		}
	}
	// Add an extra line feed for good measure
	printf("\n");
}
int compare(char *source, char *cache, int buffer_size)
{
	int i;
	for (i =0; i < buffer_size; i++)
	{
		if(source[i] != cache[i])
		    return 0;
	}
	return 1;
}

int is_invalid(long address, FILE *invalid)
{
	char *line;
     line = (char*) malloc (1024);

     rewind(invalid);
     while ( fscanf(invalid,"%s\n",line) != EOF) {
	     if (address == atol(line)){
			free(line);
		printf("Ivalidated %llu\n",address);
			return 1;
		}
 	} 
     free(line);
     return 0; 
}

int main (int argc, char *argv[])
{
  FILE *source,*cache,*input,*invalid;
  char *buffer;
  char *line,*line1;
  long address;
   char *page_source, *page_cache;

  cache = fopen ("/dev/sda6","rb");
  source = fopen ("/dev/dm-cache/lv-node2-disk","rb");
  input = fopen (argv[1],"r+");
  invalid = fopen (argv[2],"r+");

  
  if (source==NULL) {fputs ("File error",stderr); exit (1);}
  if (cache==NULL) {fputs ("File error",stderr); exit (1);}

  buffer = (char*) malloc (1024);
  line = (char*) malloc (1024);

  page_source = (char*) malloc (512);
  page_cache = (char*) malloc (512);


  while ( fscanf(input,"%s\n",line) != EOF) {  
	  address = atol(line);

	  fseek(source,address*512,SEEK_SET);
          fread(page_source,512,1,source);

	  fseek(cache,address*512,SEEK_SET);
          fread(page_cache,512,1,cache);

	  //printf("<%x>\n",address);
	//  if ( is_invalid(address,invalid));
	//	continue;
	  if (!compare(page_source,page_cache,512) && !(is_invalid(address,invalid))) {
		  printf("Block different at block sector: <%llu>\n",address);
//		  dump_buffer(page_source, 512);
//		  dump_buffer(page_cache, 512);
	  }
  }

  free(line);
  free(buffer);
  free(page_source);
  free(page_cache);

  fclose(invalid);
  fclose(cache);
  fclose(source); 
  fclose(input);
  return 0;
}


