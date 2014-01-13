#include "mytree.h"

int insert(char * string, struct node ** root)
{
	int cmp;

	if(*root == NULL)
	{
		*root = (struct node *)malloc(sizeof(struct node));
		(*root)->string = malloc(sizeof(char) * 4097);
		strcpy((*root)->string, string);
		(*root)->left = NULL;
		(*root)->right = NULL;
		return 1;
	}
	else
	{
		cmp = strcmp(string, (*root)->string);

		if(cmp < 0)
		{
			return insert(string, &((*root)->left));
		}
		else if(cmp > 0)
		{
			return insert(string, &((*root)->right));
		}
		else
		{
			return 0;
		}
	}
}
