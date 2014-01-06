#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/bio.h>
#include "dm.h"
#include <linux/dm-io.h>

#define TRUE 1
#define FALSE 0

struct fingerprint_store
{
	unsigned char * fingerprint;
	sector_t cacheblock;
	short int shared;
	//struct rb_node node;
	struct list_head list;
};

struct fingerprint_table
{
	struct list_head first;
	int has;
};

struct duplicate_node
{
	int device_id;
	sector_t block_index;
	sector_t sourceblock;
	sector_t cacheblock;
	int dirty;
};

struct source_tracker
{
	sector_t block_index;
	int dirty;
	struct list_head list;
};

struct reverse_node
{
	sector_t cacheblock;
	int count;
	int dirty_count;
	unsigned char * fingerprint;
	int head;
	struct list_head first;
};

struct rb_root * get_tree_root(void);
struct radix_tree_root * get_radix_root(void);
struct source_tracker * create_source_tracker(sector_t block_index, int dirty);
void add_source_tracker(struct reverse_node * reverse_node, struct source_tracker * source_tracker);
void remove_source_tracker(struct reverse_node * reverse_node, sector_t block_index);
void remove_device(struct radix_tree_root * duplicate_tree, struct reverse_node * reverse_node, sector_t device_id);
void remove_all(struct radix_tree_root * duplicate_tree, struct reverse_node * reverse_node);
struct source_tracker * first_source_tracker(struct reverse_node * reverse_node);
struct duplicate_node * find_duplicate(struct radix_tree_root * duplicate_tree, sector_t block_index);
void add_duplicate(struct radix_tree_root * duplicate_tree, sector_t block_index, int device_id, sector_t sourceblock, sector_t cacheblock, int dirty);
void remove_duplicate(struct radix_tree_root * duplicate_tree, sector_t block_index);
struct fingerprint_table * create_fingerprint_table(sector_t size);
//struct fingerprint_store * find_fingerprint(struct rb_root * fingerprint_tree, unsigned char * fingerprint);
struct fingerprint_store * find_fingerprint(struct fingerprint_table * table, unsigned char * fingerprint, sector_t length);
//void add_fingerprint(struct rb_root * fingerprint_tree, unsigned char * fingerprint, sector_t cacheblock);
void add_fingerprint(struct fingerprint_table * table, unsigned char * fingerprint, sector_t cacheblock, sector_t length);
//void remove_fingerprint(struct rb_root * fingerprint_tree, unsigned char * fingerprint);
void remove_fingerprint(struct fingerprint_table * table, unsigned char * fingerprint, sector_t length);
struct reverse_node * find_reverse(struct radix_tree_root * reverse_tree, sector_t cacheblock);
struct reverse_node * create_reverse_node(sector_t cacheblock, int count, unsigned char * fingerprint, int dirty);
//void add_reverse(struct radix_tree_root * reverse_tree, sector_t cacheblock, int count, unsigned char * fingerprint, int dirty);
void add_reverse(struct radix_tree_root * reverse_tree, struct reverse_node * reverse_node);
void remove_reverse(struct radix_tree_root * reverse_tree, sector_t cacheblock);
int make_fingerprint(struct bio * bio, unsigned char * result, sector_t block_size);
