#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node
{
	char * string;
	struct node * left;
	struct node * right;
};

int insert(char * string, struct node ** root);
