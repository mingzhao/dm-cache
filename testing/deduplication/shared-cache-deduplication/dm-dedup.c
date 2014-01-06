#include "dm-dedup2.h"

struct rb_root * get_tree_root(void)
{
	struct rb_root * tree_root;

	tree_root = kmalloc(sizeof(tree_root), GFP_KERNEL);
	*tree_root = RB_ROOT;
	return tree_root;
}

struct radix_tree_root * get_radix_root(void)
{
	struct radix_tree_root * radix;
	
	radix = (struct radix_tree_root *) vmalloc(sizeof(*radix));
 	INIT_RADIX_TREE(radix, GFP_NOIO);
 	return radix;
}

int to_integer(unsigned char * a_string, sector_t length)
{
	int result = 0;
	int i;
	int hold;

	for(i = 0; i < 16; i++)
	{
		hold = a_string[i];
		result = ((result * 16) + hold) % length;
	}

	return result;
}

struct source_tracker * create_source_tracker(sector_t block_index, int dirty)
{
	struct source_tracker * source_tracker;

	source_tracker = (struct source_tracker *)kmalloc(sizeof(* source_tracker), GFP_KERNEL);
	source_tracker->block_index = block_index;
	source_tracker->dirty = dirty;
	INIT_LIST_HEAD(&source_tracker->list);

	return source_tracker;
}

void add_source_tracker(struct reverse_node * reverse_node, struct source_tracker * source_tracker)
{
	if(reverse_node->head == 0)
	{
		INIT_LIST_HEAD(&reverse_node->first);
		list_add(&(source_tracker->list), &(reverse_node->first));
		reverse_node->head = 1;
	}
	else
	{
		list_add(&(source_tracker->list), &(reverse_node->first));
	}
}

void remove_source_tracker(struct reverse_node * reverse_node, sector_t block_index)
{
	struct source_tracker * post;
	struct source_tracker * n;
	struct source_tracker * tmp;

	post = NULL;
	n = NULL;
	tmp = NULL;

	list_for_each_entry_safe(post, n, &reverse_node->first, list)
	{
		tmp = list_entry(&post->list, struct source_tracker, list);

		if(tmp->block_index == block_index)
		{
			if(tmp->dirty == 1)
			{
				reverse_node->dirty_count--;
			}		

			list_del(&post->list);
			kfree(tmp);
			return;
		}
	}
}

void remove_device(struct radix_tree_root * duplicate_tree, struct reverse_node * reverse_node, sector_t device_id)
{
	struct source_tracker * post;
	struct source_tracker * n;
	struct source_tracker * tmp;
	struct duplicate_node * duplicate_node;

	post = NULL;
	n = NULL;
	tmp = NULL;

	list_for_each_entry_safe(post, n, &reverse_node->first, list)
	{
		tmp = list_entry(&post->list, struct source_tracker, list);
		duplicate_node = find_duplicate(duplicate_tree, tmp->block_index);
		

		if(duplicate_node->device_id == device_id)
		{		
			reverse_node->count--;
			list_del(&post->list);
			kfree(tmp);
			radix_tree_delete(duplicate_tree, duplicate_node->block_index);
			kfree(duplicate_node);
		}
	}
}

void remove_all(struct radix_tree_root * duplicate_tree, struct reverse_node * reverse_node)
{
	struct source_tracker * post;
	struct source_tracker * n;
	struct source_tracker * tmp;
	struct duplicate_node * duplicate_node;

	post = NULL;
	n = NULL;
	tmp = NULL;

	list_for_each_entry_safe(post, n, &reverse_node->first, list)
	{
		tmp = list_entry(&post->list, struct source_tracker, list);
		reverse_node->count--;
		list_del(&post->list);
		duplicate_node = radix_tree_delete(duplicate_tree, tmp->block_index);

		if(duplicate_node != NULL)
		{
			kfree(duplicate_node);
		}

		//kfree(tmp);
	}	
}

struct source_tracker * first_source_tracker(struct reverse_node * reverse_node)
{
	struct source_tracker * post;
	struct source_tracker * n;
	struct source_tracker * tmp;

	post = NULL;
	n = NULL;
	tmp = NULL;

	if(reverse_node->head = 0)
	{
		return NULL;
	}

	list_for_each_entry_safe(post, n, &reverse_node->first, list)
	{
		tmp = list_entry(&post->list, struct source_tracker, list);
		return tmp;
	}

	return NULL;
}

struct duplicate_node * find_duplicate(struct radix_tree_root * duplicate_tree, sector_t block_index)
{
	struct duplicate_node * duplicate_node;
	duplicate_node = radix_tree_lookup(duplicate_tree, block_index);

	return duplicate_node;
}

struct duplicate_node * create_duplicate_node(sector_t block_index, int device_id, sector_t sourceblock, sector_t cacheblock, int dirty)
{
	struct duplicate_node * duplicate_node;

	duplicate_node = (struct duplicate_node *)kmalloc(sizeof(* duplicate_node), GFP_KERNEL);
	duplicate_node->block_index = block_index;
	duplicate_node->device_id = device_id;
	duplicate_node->sourceblock = sourceblock;
	duplicate_node->cacheblock = cacheblock;
	duplicate_node->dirty = dirty;

	return duplicate_node;
}

void add_duplicate(struct radix_tree_root * duplicate_tree, sector_t block_index, int device_id, sector_t sourceblock, sector_t cacheblock, int dirty)
{
	struct duplicate_node * duplicate_node;
	duplicate_node = create_duplicate_node(block_index, device_id, sourceblock, cacheblock, dirty);
	radix_tree_insert(duplicate_tree, block_index, (void *) duplicate_node);
	/*printk("Adding duplicate_node\n");
	printk("Block index: %llu\n", block_index);
	printk("source: %llu\n", sourceblock);
	printk("device: %d\n", device_id);
	printk("cache: %llu\n", cacheblock);
	printk("dirty: %llu\n", dirty);*/
}

void remove_duplicate(struct radix_tree_root * duplicate_tree, sector_t block_index)
{
	struct duplicate_node * duplicate_node = radix_tree_delete(duplicate_tree, block_index);

	if(duplicate_node == NULL)
	{
		printk("Duplicate %llu not removed\n", block_index);
	}
	else
	{
		//kfree(duplicate_node);
	}
}

int fingerprint_compare(unsigned char * fp1, unsigned char * fp2)
{
	return memcmp(fp1, fp2, 16);
}

/*struct fingerprint_store * find_fingerprint(struct rb_root * fingerprint_tree, unsigned char * fingerprint)
{
	struct rb_node * node = fingerprint_tree->rb_node;
	struct fingerprint_store * fingerprint_store;
	int comparison;

	while(node)
	{
		fingerprint_store = rb_entry(node, struct fingerprint_store, node);
		comparison = fingerprint_compare(fingerprint, fingerprint_store->fingerprint);

		if(comparison < 0)
		{
			node = node->rb_left;
		}
		else if(comparison > 0)
		{
			node = node->rb_right;
		}
		else
		{
			return fingerprint_store;
		}
	}

	return NULL;
}*/

struct fingerprint_store * find_fingerprint(struct fingerprint_table * table, unsigned char * fingerprint, sector_t length)
{
	int index = to_integer(fingerprint, length);
	printk("Index = %d\n", index);
	struct fingerprint_table * bucket = &table[index];
	struct fingerprint_store * post;
	struct fingerprint_store * n;
	struct fingerprint_store * tmp;
	int cmp;

	post = NULL;
	n = NULL;
	tmp = NULL;

	if(bucket->has == 0)
	{
		printk("Chosen bucket has nothing\n");
		return NULL;
	}

	list_for_each_entry_safe(post, n, &bucket->first, list)
	{
		tmp = list_entry(&post->list, struct fingerprint_store, list);
		cmp = fingerprint_compare(fingerprint, tmp->fingerprint);
		printk("Comparison: %d\n", cmp);

		if(cmp == 0)
		{
			printk("Matching fingerprint found\n");
			return tmp;
		}
	}

	return NULL;
}

/*struct fingerprint_store * create_fingerprint_store(unsigned char * fingerprint, sector_t cacheblock)
{
	struct fingerprint_store * fingerprint_store;

	fingerprint_store = (struct fingerprint_store *)kmalloc(sizeof(* fingerprint_store), GFP_KERNEL);
	fingerprint_store->fingerprint = fingerprint;
	fingerprint_store->cacheblock = cacheblock;
	fingerprint_store->shared = FALSE;

	return fingerprint_store;
}*/

struct fingerprint_table * create_fingerprint_table(sector_t size)
{
	//struct fingerprint_table * table = (struct fingerprint_table *)kmalloc(sizeof(struct fingerprint_table) * size, GFP_KERNEL);
	struct fingerprint_table * table = (struct fingerprint_table *) vmalloc(size * (sizeof(struct fingerprint_table)));
	int i;

	for(i = 0; i < size; i++)
	{
		table[i].has = 0;
	}

	return table;
}

struct fingerprint_store * create_fingerprint_store(unsigned char * fingerprint, sector_t cacheblock)
{
	struct fingerprint_store * fingerprint_store;

	fingerprint_store = (struct fingerprint_store *)kmalloc(sizeof(* fingerprint_store), GFP_KERNEL);
	fingerprint_store->fingerprint = fingerprint;
	fingerprint_store->cacheblock = cacheblock;
	fingerprint_store->shared = FALSE;
	INIT_LIST_HEAD(&fingerprint_store->list);

	return fingerprint_store;
}

/*void add_fingerprint(struct rb_root * fingerprint_tree, unsigned char * fingerprint, sector_t cacheblock)
{
	struct rb_node ** link = &fingerprint_tree->rb_node, *parent;
	struct fingerprint_store * fingerprint_store;
	struct fingerprint_store * new_fingerprint_store;
	int comparison;

	parent = NULL;

	while(*link)
	{
		parent = *link;
		fingerprint_store = rb_entry(parent, struct fingerprint_store, node);
		comparison = fingerprint_compare(fingerprint, fingerprint_store->fingerprint);

		if(comparison < 0)
		{
			link = &(*link)->rb_left;
		}
		else
		{
			link = &(*link)->rb_right;
		}
	}

	new_fingerprint_store = create_fingerprint_store(fingerprint, cacheblock);

	rb_link_node(&new_fingerprint_store->node, parent, link);
	rb_insert_color(&new_fingerprint_store->node, fingerprint_tree);
}*/

void add_fingerprint(struct fingerprint_table * table, unsigned char * fingerprint, sector_t cacheblock, sector_t length)
{
	int index = to_integer(fingerprint, length);
	struct fingerprint_table * bucket = &table[index];
	struct fingerprint_store * fingerprint_store = create_fingerprint_store(fingerprint, cacheblock);

	if(bucket->has == 0)
	{
		INIT_LIST_HEAD(&bucket->first);
		list_add(&(fingerprint_store->list), &(bucket->first));
		bucket->has = 1;
	}
	else
	{
		list_add(&(fingerprint_store->list), &(bucket->first));
	}
}

/*void remove_fingerprint(struct rb_root * fingerprint_tree, unsigned char * fingerprint)
{
	struct rb_node * node = fingerprint_tree->rb_node;
	struct fingerprint_store * fingerprint_store;
	int comparison;

	while(node)
	{
		fingerprint_store = rb_entry(node, struct fingerprint_store, node);

		if(fingerprint_store->fingerprint == NULL)
		{
			printk("NULLLLLLLLLLLLLL!!!!!!\n");
		}

		comparison = fingerprint_compare(fingerprint, fingerprint_store->fingerprint);

		if(comparison < 0)
		{
			node = node->rb_left;
		}
		else if(comparison > 0)
		{
			node = node->rb_right;
		}
		else
		{
			rb_erase(node, fingerprint_tree);
			kfree(fingerprint_store);
			return;
		}
	}
}*/

void remove_fingerprint(struct fingerprint_table * table, unsigned char * fingerprint, sector_t length)
{
	int index = to_integer(fingerprint, length);
	printk("Removing a fingerprint from index %d\n", index);
	struct fingerprint_table * bucket = &table[index];
	struct fingerprint_store * post;
	struct fingerprint_store * n;
	struct fingerprint_store * tmp;
	int cmp;

	post = NULL;
	n = NULL;
	tmp = NULL;

	if(bucket->has == 0)
	{
		printk("This bucket is empty\n");
		return;
	}

	list_for_each_entry_safe(post, n, &bucket->first, list)
	{
		tmp = list_entry(&post->list, struct fingerprint_store, list);
		cmp = fingerprint_compare(fingerprint, tmp->fingerprint);
		printk("Comp = %d\n", cmp);

		if(cmp == 0)
		{
			printk("Removing a match\n");
			list_del(&post->list);
			//kfree(tmp->fingerprint);
			//kfree(tmp);
			return;
		}
	}
}

struct reverse_node * find_reverse(struct radix_tree_root * reverse_tree, sector_t cacheblock)
{
	struct reverse_node * reverse_node;
	reverse_node = radix_tree_lookup(reverse_tree, cacheblock);

	return reverse_node;
}

struct reverse_node * create_reverse_node(sector_t cacheblock, int count, unsigned char * fingerprint, int dirty)
{
	struct reverse_node * reverse_node;

	reverse_node = (struct reverse_node *)kmalloc(sizeof(* reverse_node), GFP_KERNEL);
	reverse_node->cacheblock = cacheblock;
	reverse_node->count = count;
	reverse_node->dirty_count = dirty;
	reverse_node->fingerprint = fingerprint;
	reverse_node->head = 0;

	return reverse_node; 
}

/*void add_reverse(struct radix_tree_root * reverse_tree, sector_t cacheblock, int count, unsigned char * fingerprint, int dirty)
{
	struct reverse_node * reverse_node;
	reverse_node = create_reverse_node(cacheblock, count, fingerprint, dirty);
	radix_tree_insert(reverse_tree, cacheblock, (void *) reverse_node);
	printk("adding reverse_node\n");
	printk("cache: %llu\n", cacheblock);
	printk("count: %d\n", count);
}*/

void add_reverse(struct radix_tree_root * reverse_tree, struct reverse_node * reverse_node)
{
	radix_tree_insert(reverse_tree, reverse_node->cacheblock, reverse_node);
}

void remove_reverse(struct radix_tree_root * reverse_tree, sector_t cacheblock)
{
	struct reverse_node * reverse_node = radix_tree_delete(reverse_tree, cacheblock);

	if(reverse_node != NULL)
	{
		//kfree(reverse_node->fingerprint);
		//kfree(reverse_node);
	}
}

int make_fingerprint(struct bio * bio, unsigned char * result, sector_t block_size)
{
	struct scatterlist sg;
  	struct crypto_hash *tfm;
  	struct hash_desc desc;
  	unsigned char buffer[block_size * 512];
  	unsigned int i, size, length;
  	struct page * cpy;
  	struct bio_vec * bvec;
  	int segno;
  	unsigned char * temp_data; 
  	unsigned char * write_data; 

  	size = block_size * 512;
  	length = 0;
  	write_data = NULL;

  	printk("make_fingerprint\n");

  	memset(result, 0x00, 16);

  	bio_for_each_segment(bvec, bio, segno)
  	{
	    	if(segno == 0)
	    	{
				cpy = bio_page(bio);
				kmap(cpy);
				write_data = (unsigned char *)page_address(cpy);
				kunmap(cpy);
				length += bvec->bv_len;
	    	}
	    	else
	    	{
				cpy = bio_page(bio);
				kmap(cpy);
				temp_data = strcat(write_data, (unsigned char *)page_address(cpy));
				kunmap(cpy);
				write_data = temp_data;
				length += bvec->bv_len;
	    	}
  	}	

  	for(i = 0; i < length; i++)
  	{
     		buffer[i] = write_data[i];
  	}

  	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

  	desc.tfm = tfm;
  	desc.flags = 0;

  	sg_init_one(&sg, buffer, size);
  	crypto_hash_init(&desc);

  	crypto_hash_update(&desc, &sg, size);
  	crypto_hash_final(&desc, result);
  	crypto_free_hash(tfm);

  	return 0;
}
