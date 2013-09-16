#include <linux/rbtree.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/time.h>

#define MAX_ARRAY 5    //maximum array length for every array used in the tree nodes
#define MAX_TREE 1000  //maximum number of nodes per tree
#define TRUE 1
#define FALSE 0

int fingerprint_store_size = 0;
int source_sector_map_size = 0;
int cache_sector_map_size = 0;

struct fingerprint_map {
	sector_t cache_id;
	long timestamp;
	int valid;
};

struct source_sector_map {
	int device_id;
	sector_t cache_id;
	long timestamp;
	int valid;
};

struct cache_sector_map {
	sector_t source_id;
	int device_id;
	int valid;
	int dirty;
	long timestamp;
};

struct fingerprint_node {
	unsigned char * fingerprint;
	int array_size;
	long timestamp;
	struct fingerprint_map * array;
	struct rb_node node;
};

struct source_sector_node {
	sector_t source_id;
	int array_size;
	long timestamp;
	struct source_sector_map * array;
	struct rb_node node;
};

struct cache_sector_node {
	sector_t cache_id;
	int array_size;
	unsigned char * fingerprint;
	long timestamp;
	struct cache_sector_map * array;
	struct rb_node node;
};

static struct rb_root * get_fingerprint_tree(void);
static struct rb_root * get_source_sector_tree(void);
static struct rb_root * get_cache_sector_tree(void);

static struct source_sector_node * search_for_source_sector_node(struct rb_root * source_sector_tree, sector_t source_sector);
static struct source_sector_map * search_for_source_sector_map(struct source_sector_map * array, int device_id);
static void update_source_sector_map(struct source_sector_map * source_sector_map);
static void update_source_sector_node(struct source_sector_node * source_sector_node);
static struct cache_sector_node * search_for_cache_sector_node(struct rb_root * cache_sector_tree, sector_t cache_sector);
static struct cache_sector_map * search_for_cache_sector_map(struct cache_sector_map * array, sector_t source_sector, int device_id);
static void update_cache_sector_map(struct cache_sector_map * cache_sector_map);
static void update_cache_sector_node(struct cache_sector_node * cache_sector_node);
static int fingerprint_compare(unsigned char * fp1, unsigned char * fp2);
static struct fingerprint_node * search_for_fingerprint_node(struct rb_root * fingerprint_tree, unsigned char * fingerprint);
static struct fingerprint_map * search_for_fingerprint_map(struct fingerprint_map * array, sector_t cache_sector);
static void update_fingerprint_map(struct fingerprint_map * fingerprint_map);
static void update_fingerprint_node(struct fingerprint_node * fingerprint_node);
static void invalidate_fingerprint_map(struct fingerprint_map * fingerprint_map, struct fingerprint_node * fingerprint_node, struct rb_root * fingerprint_tree);
static void invalidate_cache_sector_map(struct cache_sector_map * cache_sector_map, struct cache_sector_node * cache_sector_node, struct rb_root * cache_sector_tree);
static void invalidate_source_sector_map(struct source_sector_map * source_sector_map, struct source_sector_node * source_sector_node, struct rb_root * source_sector_tree);
static void destroy_source_sector_node(struct source_sector_node * source_sector_node, struct rb_root * source_sector_tree);
static void destroy_cache_sector_node(struct cache_sector_node * cache_sector_node, struct rb_root * cache_sector_tree);
static void destroy_fingerprint_node(struct fingerprint_node * fingerprint_node, struct rb_root * fingerprint_tree);

static struct rb_root * get_fingerprint_tree(void)
{
	struct rb_root * fingerprint_tree;
	fingerprint_tree = kmalloc(sizeof(fingerprint_tree), GFP_KERNEL);
	*fingerprint_tree = RB_ROOT;
	return fingerprint_tree;
}

static struct rb_root * get_source_sector_tree(void)
{
	struct rb_root * source_sector_tree;
	source_sector_tree = kmalloc(sizeof(source_sector_tree), GFP_KERNEL);
	*source_sector_tree = RB_ROOT;
	return source_sector_tree;
}

static struct rb_root * get_cache_sector_tree(void)
{
	struct rb_root * cache_sector_tree;
	cache_sector_tree = kmalloc(sizeof(cache_sector_tree), GFP_KERNEL);
	*cache_sector_tree = RB_ROOT;
	return cache_sector_tree;
}

static struct source_sector_node * search_for_source_sector_node(struct rb_root * source_sector_tree, sector_t source_sector)
{
	struct rb_node * node = source_sector_tree->rb_node;
	struct source_sector_node * source_sector_node;


	while(node)
	{
		source_sector_node = rb_entry(node, struct source_sector_node, node);

		if(source_sector < source_sector_node->source_id)
		{
			node = node->rb_left;
		}
		else if(source_sector > source_sector_node->source_id)
		{
			node = node->rb_right;
		}
		else
		{
			update_source_sector_node(source_sector_node);
			return source_sector_node;
		}
	}

	return NULL;
}

static struct source_sector_map * search_for_source_sector_map(struct source_sector_map * array, int device_id)
{
	int i;

	for(i = 0; i < MAX_ARRAY; i++)
	{
		if(array[i].valid == TRUE)
		{
			if(array[i].device_id == device_id)
			{
				update_source_sector_map(&array[i]);
				return &array[i];
			}
		}
	}

	return NULL;
}

static void update_source_sector_map(struct source_sector_map * source_sector_map)
{
	struct timespec * ts;
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);
	source_sector_map->timestamp = ts->tv_nsec;
	kfree(ts);
}

static void update_source_sector_node(struct source_sector_node * source_sector_node)
{
	struct timespec * ts;
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);
	source_sector_node->timestamp = ts->tv_nsec;
	kfree(ts);
}

static struct cache_sector_node * search_for_cache_sector_node(struct rb_root * cache_sector_tree, sector_t cache_sector)
{
	struct rb_node * node = cache_sector_tree->rb_node;
	struct cache_sector_node * cache_sector_node;


	while(node)
	{
		cache_sector_node = rb_entry(node, struct cache_sector_node, node);

		if(cache_sector < cache_sector_node->cache_id)
		{
			node = node->rb_left;
		}
		else if(cache_sector > cache_sector_node->cache_id)
		{
			node = node->rb_right;
		}
		else
		{
			update_cache_sector_node(cache_sector_node);
			return cache_sector_node;
		}
	}

	return NULL;
}

static struct cache_sector_map * search_for_cache_sector_map(struct cache_sector_map * array, sector_t source_sector, int device_id)
{
	int i;

	for(i = 0; i < MAX_ARRAY; i++)
	{
		if(array[i].valid == TRUE)
		{
			if(array[i].source_id == source_sector && array[i].device_id == device_id)
			{
				update_cache_sector_map(&array[i]);
				return &array[i];
			}
		}
	}

	return NULL;
}

static void update_cache_sector_map(struct cache_sector_map * cache_sector_map)
{
	struct timespec * ts;
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);
	cache_sector_map->timestamp = ts->tv_nsec;
	kfree(ts);
}

static void update_cache_sector_node(struct cache_sector_node * cache_sector_node)
{
	struct timespec * ts;
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);
	cache_sector_node->timestamp = ts->tv_nsec;
	kfree(ts);
}

static int fingerprint_compare(unsigned char * fp1, unsigned char * fp2)
{
	return memcmp(fp1, fp2, 16);
}


static struct fingerprint_node * search_for_fingerprint_node(struct rb_root * fingerprint_tree, unsigned char * fingerprint)
{
	struct rb_node * node = fingerprint_tree->rb_node;
	struct fingerprint_node * fingerprint_node;
	int compare_result;


	while(node)
	{
		fingerprint_node = rb_entry(node, struct fingerprint_node, node);
		compare_result = fingerprint_compare(fingerprint, fingerprint_node->fingerprint);

		if(compare_result < 0)
		{
			node = node->rb_left;
		}
		else if(compare_result > 0)
		{
			node = node->rb_right;
		}
		else
		{
			update_fingerprint_node(fingerprint_node);
			return fingerprint_node;
		}
	}

	return NULL;
}

static struct fingerprint_map * search_for_fingerprint_map(struct fingerprint_map * array, sector_t cache_sector)
{
	int i;

	for(i = 0; i < MAX_ARRAY; i++)
	{
		if(array[i].valid == TRUE)
		{
			if(array[i].cache_id == cache_sector)
			{
				update_fingerprint_map(&array[i]);
				return &array[i];
			}
		}
	}

	return NULL;
}

static void update_fingerprint_map(struct fingerprint_map * fingerprint_map)
{
	struct timespec * ts;
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);
	fingerprint_map->timestamp = ts->tv_nsec;
	kfree(ts);
}

static void update_fingerprint_node(struct fingerprint_node * fingerprint_node)
{
	struct timespec * ts;
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);
	fingerprint_node->timestamp = ts->tv_nsec;
	kfree(ts);
}

static void invalidate_fingerprint_map(struct fingerprint_map * fingerprint_map, struct fingerprint_node * fingerprint_node, struct rb_root * fingerprint_tree)
{
	fingerprint_map->valid = FALSE;
	fingerprint_node->array_size--;

	if(fingerprint_node->array_size == 0)
	{
		destroy_fingerprint_node(fingerprint_node, fingerprint_tree);
	}
}

static void invalidate_cache_sector_map(struct cache_sector_map * cache_sector_map, struct cache_sector_node * cache_sector_node, struct rb_root * cache_sector_tree)
{
	cache_sector_map->valid = FALSE;
	cache_sector_node->array_size--;

	if(cache_sector_node->array_size == 0)
	{
		destroy_cache_sector_node(cache_sector_node, cache_sector_tree);
	}
}

static void invalidate_source_sector_map(struct source_sector_map * source_sector_map, struct source_sector_node * source_sector_node, struct rb_root * source_sector_tree)
{
	source_sector_map->valid = FALSE;
	source_sector_node->array_size--;

	if(source_sector_node->array_size == 0)
	{
		destroy_source_sector_node(source_sector_node, source_sector_tree);
	}
}

static void destroy_source_sector_node(struct source_sector_node * source_sector_node, struct rb_root * source_sector_tree)
{
	struct rb_node * node = source_sector_tree->rb_node;
	struct source_sector_node * current_source_node;

	while(node)
	{
		current_source_node = rb_entry(node, struct source_sector_node, node);

		if(source_sector_node->source_id < current_source_node->source_id)
		{
			node = node->rb_left;
		}
		else if(source_sector_node->source_id > current_source_node->source_id)
		{
			node = node->rb_right;
		}
		else
		{
			rb_erase(node, source_sector_tree);
			kfree(source_sector_node->array);
			kfree(source_sector_node);
			source_sector_map_size--;
		}
	}
}

static void destroy_cache_sector_node(struct cache_sector_node * cache_sector_node, struct rb_root * cache_sector_tree)
{
	struct rb_node * node = cache_sector_tree->rb_node;
	struct cache_sector_node * current_cache_node;

	while(node)
	{
		current_cache_node = rb_entry(node, struct cache_sector_node, node);

		if(cache_sector_node->cache_id < current_cache_node->cache_id)
		{
			node = node->rb_left;
		}
		else if(cache_sector_node->cache_id > current_cache_node->cache_id)
		{
			node = node->rb_right;
		}
		else
		{
			rb_erase(node, cache_sector_tree);
			kfree(cache_sector_node->array);
			kfree(cache_sector_node);
			cache_sector_map_size--;
		}
	}
}

static void destroy_fingerprint_node(struct fingerprint_node * fingerprint_node, struct rb_root * fingerprint_tree)
{
	struct rb_node * node = fingerprint_tree->rb_node;
	struct fingerprint_node * current_fingerprint_node;
	int compare_result;


	while(node)
	{
		current_fingerprint_node = rb_entry(node, struct fingerprint_node, node);
		compare_result = fingerprint_compare(fingerprint_node->fingerprint, current_fingerprint_node->fingerprint);

		if(compare_result < 0)
		{
			node = node->rb_left;
		}
		else if(compare_result > 0)
		{
			node = node->rb_right;
		}
		else
		{
			rb_erase(node, fingerprint_tree);
			kfree(fingerprint_node->array);
			kfree(fingerprint_node->fingerprint);
			kfree(fingerprint_node);
			fingerprint_store_size--;
		}
	}
}