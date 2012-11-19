#include <linux/slab.h>
#include <linux/string.h>

//Stores a single mapping between a source sector and cache sector
struct sector_map
{
	sector_t source_sector;
	sector_t cache_sector;
};

//Stores a single fingerprint along with a list of matching cacheblocks
struct fingerprint_store
{
	unsigned char * fingerprint;
	sector_t * cachelist;
	int max_length;
	int element_count;
};

//Represents a reference to a source sector and whether it is clean or dirty according to the cacheblock that holds its data
struct sector_status
{
	sector_t source_sector;
	int status;
};

struct sector_status_list
{
	struct sector_status * sector_status;
	int max_length;
	int element_count;
};

struct fingerprint_list
{
	struct fingerprint_store * fingerprint_store;
	int length;
};

struct sector_map_list
{
	struct sector_map * sector_map;
	int length;
};

//Initializes a list of fingerprint stores
struct fingerprint_list * init_fingerprint_list(int length)
{
	struct fingerprint_list * new_fingerprint_list;
	struct fingerprint_store * new_fingerprint_store;
	int i;

	new_fingerprint_store = kmalloc(sizeof(struct fingerprint_store) * length, GFP_KERNEL);

	for(i = 0; i < length; i++)
	{
		new_fingerprint_store[i].fingerprint = NULL;
		new_fingerprint_store[i].cachelist = NULL;
		new_fingerprint_store[i].max_length = 0;
		new_fingerprint_store[i].element_count = 0;
	}

	new_fingerprint_list = kmalloc(sizeof(struct fingerprint_list), GFP_KERNEL);
	new_fingerprint_list->fingerprint_store = new_fingerprint_store;
	new_fingerprint_list->length = length;

	return new_fingerprint_list;
}

/*Search the fingerprint list and return the matching fingerprint store*/

struct fingerprint_store * search_fingerprint_list(struct fingerprint_list * fingerprint_list, unsigned char * fingerprint)
{
	int i, length;
	length = fingerprint_list->length;

	for(i = 0; i < length; i++)
	{
		if(fingerprint_list->fingerprint_store[i].fingerprint != NULL)
		{
			if(memcmp(fingerprint_list->fingerprint_store[i].fingerprint, fingerprint, 16) == 0)
			{
				return &fingerprint_list->fingerprint_store[i];
			}
		}
	}

	return NULL;
}

sector_t * add_to_integer_array(sector_t * integer_array, int * max_length, int element_count, sector_t new_element)
{
	int boolean, i;
	sector_t * new_integer_array;
	boolean = 0;

	if(integer_array != NULL)
	{
		for(i = 0; i < *max_length; i++)
		{
			if(integer_array[i] == -1)
			{
				integer_array[i] = new_element;
				boolean = 1;
				break;
			}
		}
	}

	if(boolean == 1)
	{
		return integer_array;
	}
	else
	{
		if(integer_array == NULL)
		{
			integer_array = (sector_t *)kmalloc(sizeof(unsigned long long), GFP_KERNEL);
			integer_array[0] = new_element;
			*max_length = 1;
			return integer_array;
		}
		else
		{
			new_integer_array = (sector_t *)kmalloc(sizeof(unsigned long long) * (*max_length) * 2, GFP_KERNEL);

			for(i = 0; i < *max_length; i++)
			{
				new_integer_array[i] = integer_array[i];
			}

			*max_length *= 2;
			new_integer_array[i] = new_element;
			i++;

			while(i < *max_length)
			{
				new_integer_array[i] = -1;
				i++;
			}

			return new_integer_array;
		}
	}
}

/*Inserts a fingerprint - cacheblock pair into the fingerprint list. If the fingerprint already exists, just tack on the cacheblock to the list of cacheblocks for that fingerprint*/

void insert_into_fingerprint_list(struct fingerprint_list * fingerprint_list, unsigned char * fingerprint, sector_t cache_sector)
{
	struct fingerprint_store * fingerprint_store;
	int i;

	fingerprint_store = search_fingerprint_list(fingerprint_list, fingerprint);

	if(fingerprint_store == NULL)
	{
		for(i = 0; i < fingerprint_list->length; i++)
		{
			if(fingerprint_list->fingerprint_store[i].fingerprint == NULL)
			{
				fingerprint_list->fingerprint_store[i].cachelist = add_to_integer_array(fingerprint_list->fingerprint_store[i].cachelist, &fingerprint_list->fingerprint_store[i].max_length, fingerprint_list->fingerprint_store[i].element_count, cache_sector);
				fingerprint_list->fingerprint_store[i].fingerprint = fingerprint;
				fingerprint_list->fingerprint_store[i].element_count++;
				return;
			}
		}
	}
	else
	{
		fingerprint_store->cachelist = add_to_integer_array(fingerprint_store->cachelist, &fingerprint_store->max_length, fingerprint_store->element_count, cache_sector);
		fingerprint_store->element_count++;
		return;
	}
}

sector_t * remove_from_integer_array(sector_t * integer_array, int * max_length, sector_t old_element)
{
	int i;

	for(i = 0; i < *max_length; i++)
	{
		if(integer_array[i] == old_element)
		{
			integer_array[i] = -1;
			break;
		}
	}

	return integer_array;
}

/*Remove a cacheblock for a specified fingerprint. If the fingerprint has no more referencing cacheblocks, remove it */

void remove_from_fingerprint_list(struct fingerprint_list * fingerprint_list, unsigned char * fingerprint, sector_t cache_sector)
{
	struct fingerprint_store * fingerprint_store;

	fingerprint_store = search_fingerprint_list(fingerprint_list, fingerprint);

	if(fingerprint_store != NULL)
	{
		fingerprint_store->cachelist = remove_from_integer_array(fingerprint_store->cachelist, &fingerprint_store->max_length, cache_sector);
		fingerprint_store->element_count--;

		if(fingerprint_store->element_count == 0)
		{
			fingerprint_store->fingerprint = NULL;
			fingerprint_store->cachelist = NULL;
			fingerprint_store->max_length = 0;
		}
	}
}

/*Initializes a list of sector maps */

struct sector_map_list * init_sector_map_list(int length)
{
	struct sector_map_list * new_sector_map_list;
	struct sector_map * new_sector_map;
	int i;

	new_sector_map = kmalloc(sizeof(struct sector_map) * length, GFP_KERNEL);

	for(i = 0; i < length; i++)
	{
		new_sector_map[i].source_sector = -1;
		new_sector_map[i].cache_sector = -1;
	}

	new_sector_map_list = kmalloc(sizeof(struct sector_map_list), GFP_KERNEL);
	new_sector_map_list->sector_map = new_sector_map;
	new_sector_map_list->length = length;

	return new_sector_map_list;
}

/* Search a sector map by source sector */

struct sector_map * search_sector_map_list(struct sector_map_list * sector_map_list, sector_t source_sector)
{
	int i, length;

	length = sector_map_list->length;

	for(i = 0; i < length; i++)
	{
		if(sector_map_list->sector_map[i].source_sector == source_sector)
		{
			return &sector_map_list->sector_map[i];
		}
	}

	return NULL;
}

/* Insert a new sector map into the list by passing in a source and destination sector */

void insert_into_sector_map_list(struct sector_map_list * sector_map_list, sector_t source_sector, sector_t cache_sector)
{
	struct sector_map * sector_map;

	sector_map = search_sector_map_list(sector_map_list, -1);

	if(sector_map != NULL)
	{
		sector_map->source_sector = source_sector;
		sector_map->cache_sector = cache_sector;
	}
}

/* Remove a sector map from the list */

void remove_from_sector_map_list(struct sector_map_list * sector_map_list, sector_t source_sector)
{
	struct sector_map * sector_map;

	sector_map = search_sector_map_list(sector_map_list, source_sector);

	if(sector_map != NULL)
	{
		sector_map->source_sector = -1;
		sector_map->cache_sector = -1;
	}
}

/*Initialize the list of source references within a cacheblock */

struct sector_status_list * init_sector_status_list(sector_t source_sector, int status)
{
	struct sector_status_list * sector_status_list;
	struct sector_status * sector_status;

	sector_status = kmalloc(sizeof(struct sector_status), GFP_KERNEL);
	sector_status->source_sector = source_sector;
	sector_status->status = status;

	sector_status_list = kmalloc(sizeof(struct sector_status_list), GFP_KERNEL);
	sector_status_list->sector_status = sector_status;
	sector_status_list->max_length = 1;
	sector_status_list->element_count = 1;

	return sector_status_list;
}

/*Extend the list of source references in the cacheblock*/

struct sector_status * expand_sector_status(struct sector_status * sector_status, int * max_length)
{
	struct sector_status * new_sector_status;
	int i;

	new_sector_status = kmalloc(sizeof(struct sector_status) * (*max_length) * 2, GFP_KERNEL);

	for(i = 0; i < *max_length; i++)
	{
		new_sector_status[i].source_sector = sector_status[i].source_sector;
		new_sector_status[i].status = sector_status[i].status;
	}

	*max_length *= 2;

	while(i < *max_length)
	{
		new_sector_status[i].source_sector = -1;
		new_sector_status[i].status = -1;
		i++;
	}

	return new_sector_status;
}

/*Insert a new source reference into the cacheblock. If there is not enough space, the list is extended */

void insert_sector_status(struct sector_status_list * sector_status_list, sector_t source_sector, int status)
{
	int i;

	if(sector_status_list->element_count == sector_status_list->max_length)
		sector_status_list->sector_status = expand_sector_status(sector_status_list->sector_status, &sector_status_list->max_length);

	for(i = 0; i < sector_status_list->max_length; i++)
	{
		if(sector_status_list->sector_status[i].source_sector == -1)
		{
			sector_status_list->sector_status[i].source_sector = source_sector;
			sector_status_list->sector_status[i].status = status;
			sector_status_list->element_count++;
			break;
		}
	}
}

/*Remove a source reference from the cacheblock */

void remove_sector_status(struct sector_status_list * sector_status_list, sector_t source_sector)
{
	int i;

	for(i = 0; i < sector_status_list->max_length; i++)
	{
		if(sector_status_list->sector_status[i].source_sector == source_sector)
		{
			sector_status_list->sector_status[i].source_sector = -1;
			sector_status_list->sector_status[i].status = -1;
			sector_status_list->element_count--;

			if(sector_status_list->element_count == 0)
			{
				kfree(sector_status_list->sector_status);
				sector_status_list->sector_status = NULL;
			}

			break;
		}
	}
}

/*Get a source reference at a specified index in the list */

struct sector_status * source_sector_at_index(struct sector_status_list * sector_status_list, int position)
{
	if(position < sector_status_list->max_length)
		return &sector_status_list->sector_status[position];
	else
		return NULL;
}
