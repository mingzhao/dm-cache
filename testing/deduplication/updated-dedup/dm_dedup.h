#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/bio.h>
#include "dm.h"
#include <linux/dm-io.h>

struct ref
{
	sector_t radix;
	sector_t src_idx;
	int disk;
	int dirty;
	struct list_head list;
};

struct bucket
{
	struct list_head list;
	int count;
};

struct store
{
	unsigned char * fingerprint;
	sector_t cacheblock;
	struct list_head list;
};

struct ref * create_ref(sector_t radix, sector_t src_idx, int disk, int dirty);
int add_ref(struct list_head * cache_ptr, struct ref * ref);
int remove_ref(struct list_head * cache_ptr, sector_t radix);
int make_fingerprint(struct bio * bio, unsigned char * result, sector_t block_size);
struct bucket * create_fingerprint_table(sector_t size);
struct store * find_fingerprint(struct bucket * table, unsigned char * fingerprint, sector_t length);
void add_fingerprint(struct bucket * table, unsigned char * fingerprint, sector_t cacheblock, sector_t length);
void remove_fingerprint(struct bucket * table, unsigned char * fingerprint, sector_t length);













