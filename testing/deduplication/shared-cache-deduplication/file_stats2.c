#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

int partition = 4096;
int block_count = 0;
char ** blocks;
int num_blocks = 0;
int flag = 1;
int bucket = 0;
FILE ** handlers;

void insert_if_unique(char * next_block)
{
	int loop;
	int cmp;

	if(num_blocks == 0)
	{
		blocks[num_blocks++] = malloc((sizeof(char) * partition) + 1);
		strcpy(blocks[num_blocks - 1], next_block);
	}
	else
	{
		for(loop = 0; loop < num_blocks; loop++)
		{
			cmp = strcmp(next_block, blocks[loop]);

			if(cmp == 0)
			{
				return;
			}	
		}

		blocks[num_blocks++] = malloc((sizeof(char) * partition) + 1);	
		strcpy(blocks[num_blocks - 1], next_block);
	}
}

main(int argc, char * argv[])
{
	int the_char;
	int size;
	struct stat st;
	char * current_block;
	int loop = 0;
	int args;
	int file_block_count;

	if(argc < 2)
	{
		printf("Name the file(s) to be analyzed\n");
		return -1;
	}

	handlers = malloc(sizeof(FILE *) * (argc - 1));

	for(args = 1; args < argc; args++)
	{
		handlers[args - 1] = fopen(argv[args], "r");

		if(handlers[args - 1] == NULL)
		{
			printf("File path %s is invalid.\n", argv[args]);
			return -1;
		}

		stat(argv[args], &st);
		size = st.st_size;
		printf("size in bytes of %s: %d\n", argv[args], size);

		block_count += (size) / partition;
		file_block_count = (size) / partition;

		if(((size) % partition) > 0)
		{
			block_count++;
			file_block_count++;
		}

		printf("block count for %s: %d\n", argv[args], file_block_count);
	}

	printf("Total blocks: %d\n", block_count);
	blocks = malloc(sizeof(char *) * block_count);

	for(args = 1; args < argc; args++)
	{
		while((the_char = fgetc(handlers[args - 1])) != EOF)
		{
			if(flag)
			{
				current_block = malloc((sizeof(char) * partition) + 1);
				bucket = 0;
				flag = 0;
			}

			current_block[bucket++] = (char) the_char;

			if(bucket == partition)
			{
				current_block[partition] = '\0';
				flag = 1;
				insert_if_unique(current_block);
				free(current_block);
			}
		}

		if(flag == 0)
		{
			current_block[bucket] = '\0';
			insert_if_unique(current_block);
			free(current_block);
		}

		flag = 1;
	}

	printf("Unique blocks: %d\n", num_blocks);
	printf("Dedup rate: %f\n", (1 - ((double)num_blocks / block_count)) * 100);
}

