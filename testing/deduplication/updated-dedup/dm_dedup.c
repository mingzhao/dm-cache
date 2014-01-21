#include "dm_dedup.h"

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

int fingerprint_compare(unsigned char * fp1, unsigned char * fp2)
{
	return memcmp(fp1, fp2, 16);
}

struct bucket * create_fingerprint_table(sector_t size)
{
	struct bucket * table = (struct bucket *) vmalloc(size * (sizeof(struct bucket)));
	int i;

	for(i = 0; i < size; i++)
	{
		table[i].count = 0;
	}

	return table;
}

struct store * find_fingerprint(struct bucket * table, unsigned char * fingerprint, sector_t length)
{
	int index = to_integer(fingerprint, length);
	struct bucket * bucket = &table[index];
	struct store * post;
	struct store * n;
	struct store * tmp;
	int cmp;

	post = NULL;
	n = NULL;
	tmp = NULL;

	if(!bucket->count)
		return NULL;

	list_for_each_entry_safe(post, n, &bucket->list, list)
	{
		tmp = list_entry(&post->list, struct store, list);
		cmp = fingerprint_compare(fingerprint, tmp->fingerprint);

		if(cmp == 0)
			return tmp;
	}

	return NULL;
}

struct store * create_fingerprint_store(unsigned char * fingerprint, sector_t cacheblock)
{
	struct store * fingerprint_store;

	fingerprint_store = (struct store *)kmalloc(sizeof(* fingerprint_store), GFP_KERNEL);
	fingerprint_store->fingerprint = fingerprint;
	fingerprint_store->cacheblock = cacheblock;
	INIT_LIST_HEAD(&fingerprint_store->list);

	return fingerprint_store;
}

void add_fingerprint(struct bucket * table, unsigned char * fingerprint, sector_t cacheblock, sector_t length)
{
	int index = to_integer(fingerprint, length);
	struct bucket * bucket = &table[index];
	struct store * store = create_fingerprint_store(fingerprint, cacheblock);

	if(bucket->count == 0)
	{
		INIT_LIST_HEAD(&bucket->list);
		list_add(&(store->list), &(bucket->list));
		bucket->count = 1;
	}
	else
	{
		list_add(&(store->list), &(bucket->list));
		bucket->count++;
	}
}

void remove_fingerprint(struct bucket * table, unsigned char * fingerprint, sector_t length)
{
	int index = to_integer(fingerprint, length);
	struct bucket * bucket = &table[index];
	struct store * post;
	struct store * n;
	struct store * tmp;
	int cmp;

	post = NULL;
	n = NULL;
	tmp = NULL;

	if(bucket->count == 0)
	{
		return;
	}

	list_for_each_entry_safe(post, n, &bucket->list, list)
	{
		tmp = list_entry(&post->list, struct store, list);
		cmp = fingerprint_compare(fingerprint, tmp->fingerprint);

		if(cmp == 0)
		{
			list_del(&post->list);
			bucket->count--;
			return;
		}
	}
}

struct ref * create_ref(sector_t radix, sector_t src_idx, int disk, int dirty)
{
	struct ref * ref;

	ref = (struct ref *)kmalloc(sizeof(* ref), GFP_KERNEL);
	ref->radix = radix;
	ref->dirty = dirty;
	INIT_LIST_HEAD(&ref->list);

	return ref;
}

int add_ref(struct list_head * cache_ptr, struct ref * ref)
{
	list_add(&(ref->list), cache_ptr);
	return 1;
}

int remove_ref(struct list_head * cache_ptr, sector_t radix)
{
	struct ref * post;
	struct ref * n;
	struct ref * tmp;

	post = NULL;
	n = NULL;
	tmp = NULL;

	list_for_each_entry_safe(post, n, cache_ptr, list)
	{
		tmp = list_entry(&post->list, struct ref, list);

		if(tmp->radix == radix)
		{		
			list_del(&post->list);
			kfree(tmp);
			return -1;
		}
	}

	return 0;
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

















