#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <asm/types.h>
#define READ            0
#define WRITE           1

typedef unsigned long sector_t;

struct io_req {
        unsigned int sector;
        unsigned long rw;
        unsigned int size;
        unsigned int major;
        unsigned int minor;
};



void dump_buffer(char *buffer, int buffer_size)
{
	int c,i;


	for ( c=0;c<buffer_size;c++)
	{
		printf("%.2X ", buffer[c]);

		if (c % 4 == 3)
			printf(" ");
		// Display 16 bytes per line
		if (c % 16 == 15)
			printf("\n");
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

int main (int argc, char *argv[])
{
  FILE *source,*input,*invalid;
  char *buffer;
  int cache;
  char *line,*line1;
  long address;
  unsigned long long sector;

  ssize_t total;
  char *page_cache;

 // cache = open ("/dev/mapper/cache2",O_RDWR, O_DIRECT );
  int fd = open("/dev/dev_req", O_WRONLY);

  //cache = fopen ("/dev/sda6","rb");
  //cache = fopen ("/dev/dm-cache/lv-node2-disk","rb");
  input = fopen (argv[1],"r+");

 // if (cache==NULL) {fputs ("File error",stderr); exit (1);}

  line = (char*) malloc (1024);
  line1 = (char*) malloc (1024);

  page_cache = (char*) malloc (512);
  int size_read;

  while ( fscanf(input,"%s\t%llu\n",line,&sector) != EOF) {  
	  //address = atol(line);
//	 printf ("%s-%llu\n",line,sector);
	  
	 if (strcmp(line,"READ")==0){
	 printf ("%s-%llu\n",line,sector);
 //         	lseek(cache,sector*512,SEEK_SET);
	        //fread(page_cache,1,512,cache);
//	        size_read = read(cache,page_cache,512);
//		  dump_buffer(page_cache, 512);
	
		 struct io_req req = {
                .sector = sector,
                .rw = READ,
                .size = 512,
                .major = 8,
                .minor = 0,
        };

		total = write(fd, &req, sizeof(struct io_req));
		 printf("SIZE %d\n",size_read);
	}else if (strcmp(line,"WRITE")==0){
	 printf ("%s-%llu\n",line,sector);
          //	fseek(cache,sector*512,SEEK_SET);
	  //      fread(page_cache,512,1,cache);
	//	
          //	fseek(cache,address*512,SEEK_SET);
	      //  fwrite(page_cache,512,1,cache);
	}else {
	}
		
/*
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

*/
  }

  free(line);
  free(line1);
  free(page_cache);

 // close(cache);
  fclose(input);
  return 0;
}


