/****************************************************************************
 *  dm-cache.c
 *  Device mapper target for block-level disk caching
 *
 *  Copyright (C) International Business Machines Corp., 2006
 *  Copyright (C) Ming Zhao, Florida International University, 2007-2012
 *
 *  Authors: Dr. Ming Zhao, Dulcardo Arteaga, Douglas Otstott, Stephen Bromfield
 *           (dm-cache@googlegroups.com)
 *  Other contributors:
 *    Eric Van Hensbergen, Reng Zeng 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 ****************************************************************************/

#include <asm/atomic.h>
#include <asm/checksum.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/version.h>

#include "dm.h"
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>

#include "dm-dedup2.h"

//#include "wss-function.h"
#define DM_MSG_PREFIX "cache"
#define DMC_PREFIX "dm-cache: "

#define DPRINTK( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#define MIN_JOBS 4096

// enable WSS check and set limits
#define WSS_ANALYSIS 	0

// enable Deduplication
#define DEDUP 			1

/* Default cache parameters */
#define DEFAULT_CACHE_SIZE	65536
#define DEFAULT_CACHE_ASSOC	1024
#define DEFAULT_BLOCK_SIZE	8
#define CONSECUTIVE_BLOCKS	512

/* Write policy */
#define WRITE_THROUGH 	0
#define WRITE_BACK	1
#define WRITE_ALLOCATE 	2
#define DEFAULT_WRITE_POLICY WRITE_THROUGH

/* Number of pages for I/O */
#define DMCACHE_COPY_PAGES 	1024
#define DMCACHE_MIN_IOS		1024

/* States of a cache block */
#define INVALID		0
#define VALID		1	/* Valid */
#define RESERVED	2	/* Allocated but data not in place yet */
#define DIRTY		4	/* Locally modified */
#define WRITEBACK	8	/* In the process of write back */
#define WRITETHROUGH	16	/* In the process of write through */
#define WRITEALLOCATE	32	/* In the process of write allocate */

#define HASH		0	/* Use hash_long */
#define UNIFORM		1	/* Evenly distributed */
#define DEFAULT_HASHFUNC HASH

#define is_state(x, y)		(x & y)
#define set_state(x, y)		(x |= y)
#define clear_state(x, y)	(x &= ~y)
#define put_state(x, y)		(x = y)

/*
 * Validations
 */
#define SEG_SIZE_ORDER  0 
#define SEG_SIZE_BYTES  512

/*
* Virtual Cache Mapping
*/
#define MAX_SRC_DEVICES		128
#define MAX_VM_ID		128
#define DISABLED	0
#define ENABLED		1
#define EMPTY		2

int 	cnt_active_map = 0;		/* keep the number of current mappings */
int 	ctn_dm_dev = 0;		/* keep the number of total mappings   */
int	init_flag = 0;		/* use to determine the fisrt mapping */
struct bio_set *dmcache_bio_set;

/*dedup trees*/

struct radix_tree_root * duplicate_tree;
struct radix_tree_root * reverse_tree;
//struct rb_root * fingerprint_tree;
struct fingerprint_table * fingerprint_table;
int sector_size = 512;

/*
 * Cache mappings
 */
struct v_map {
	int identifier;	/* virtual machine mapping */
	char vm_id[MAX_VM_ID];

	int state;
	sector_t dev_size;
	sector_t dev_offset;

	dev_t vcache_dev;
	struct dm_dev *src_dev;
	struct dm_target *ti;

        unsigned long dirty_blocks;            /* Number of reads */
        unsigned long reads;            /* Number of reads */
        unsigned long writes;           /* Number of writes */
        unsigned long cache_hits;       /* Number of cache hits */
        unsigned long read_hits;
        unsigned long invalidates;
        unsigned long inserts;
        unsigned long misses;
        unsigned long read_misses;
        unsigned long write_misses;
        sector_t allocate;
        sector_t limit;
        sector_t wss;
};

/*
 * Cache context
 */
struct cache_c {
	struct dm_target *global_ti;	/* global dm_target to hold global cache */	
	struct dm_dev *src_dev;		/* Source device */
	struct dm_dev *cache_dev;	/* Cache device */
	struct dm_kcopyd_client *kcp_client; /* Kcopyd client for writing back data */
	
	struct radix_tree_root *cache;	/* Hash table for cache blocks */
	sector_t size;			/* Cache size */
	unsigned int bits;		/* Cache size in bits */
	unsigned int assoc;		/* Cache associativity */
	unsigned int block_size;	/* Cache block size */
	unsigned int block_shift;	/* Cache block size in bits */
	unsigned int block_mask;	/* Cache block mask */
	unsigned int consecutive_shift;	/* Consecutive blocks size in bits */
	unsigned long counter;		/* Logical timestamp of last access */
	unsigned int write_policy;	/* Cache write policy */
	sector_t dirty_blocks;		/* Number of dirty blocks */

	spinlock_t lock;		/* Lock to protect page allocation/deallocation */
	struct page_list *pages;	/* Pages for I/O */
	unsigned int nr_pages;		/* Number of pages */
	unsigned int nr_free_pages;	/* Number of free pages */
	wait_queue_head_t destroyq;	/* Wait queue for I/O completion */
	wait_queue_head_t wait_writeback;	/* Wait queue for I/O completion */
	atomic_t nr_jobs;		/* Number of I/O jobs */
	struct dm_io_client *io_client;   /* Client memory pool*/

        /* LRU List */
        struct list_head *lru;
        struct cacheblock *blocks;
        struct semaphore lru_mutex;

	/* Stats */
	unsigned long reads;		/* Number of reads */
	unsigned long writes;		/* Number of writes */
	unsigned long cache_hits;	/* Number of cache hits */
	unsigned long replace;		/* Number of cache replacements */
	unsigned long writeback;	/* Number of replaced dirty blocks */
	unsigned long dirty;		/* Number of submitted dirty blocks */

        unsigned long misses;
        unsigned long read_misses;
        unsigned long write_misses;
        unsigned long read_hits;
        unsigned long invalidates;
        unsigned long inserts;
        unsigned long allocate;

	unsigned long potential;
	unsigned long actual;
};

/* Cache block metadata structure */
struct cacheblock {
	spinlock_t lock;	/* Lock to protect operations on the bio list */
	sector_t block;		/* Sector number of the cached block */
        sector_t cacheblock;

	unsigned short state;	/* State of a block */
	struct bio_list bios;	/* List of pending bios */
	unsigned short disk;		/* Disk identifier for LV of each VM */

        struct list_head list;
};

/* Structure for a kcached job */
struct kcached_job {
	struct list_head list;
	struct cache_c *dmc;
	struct bio *bio;	/* Original bio */
	struct dm_io_region src;
	struct dm_io_region dest;
	struct cacheblock *cacheblock;
	int rw;
	int allocate;
	int vdisk;
	/*
	 * When the original bio is not aligned with cache blocks,
	 * we need extra bvecs and pages for padding.
	 */
	struct bio_vec *bvec;
	unsigned int nr_pages;
	struct page_list *pages;
};

/*****************************************************************
*	Shared structures
******************************************************************/
struct cache_c *shared_cache;
struct v_map *virtual_mapping;

static struct workqueue_struct *_kcached_wq;
static struct work_struct _kcached_work;
static struct workqueue_struct *_kallocate_wq;
static struct work_struct _kallocate_work;

static inline void wake(void)
{
	queue_work(_kcached_wq, &_kcached_work);
}

static struct kmem_cache *_job_cache;
static mempool_t *_job_pool;

static DEFINE_SPINLOCK(_job_lock);
static LIST_HEAD(_complete_jobs);
static LIST_HEAD(_io_jobs);
static LIST_HEAD(_pages_jobs);
static LIST_HEAD(_allocate_jobs);

/*****************************************************************
*	Functions
******************************************************************/
static int virtual_cache_map(struct bio *bio);
static sector_t get_block_index(sector_t block, int disk);
static void cache_flush(struct cache_c *dmc, int disk);
static int cache_write_miss(struct cache_c *dmc, struct bio* bio, int disk, struct cacheblock *allocate);
static void io_callback(unsigned long error, void *context);
static void write_back(struct cache_c *dmc, struct cacheblock *cache, unsigned int length);
static int do_complete(struct kcached_job *job);
static void flush_bios(struct cacheblock *cacheblock);
static void cache_invalidate(struct cache_c *dmc, struct cacheblock *cache);

/****************************************************************************
 *  Wrapper functions for using the new dm_io API
 ****************************************************************************/
static void dmcache_destructor(struct bio *bio)
{
	bio_free(bio, dmcache_bio_set);
}

static void nocallback_endio(struct bio *bio, int error)
{
	int i = 0;
	struct kcached_job *job = (struct kcached_job *)bio->bi_private;
	struct cache_c *dmc = job->dmc;

	if (error)
		clear_bit(BIO_UPTODATE, &bio->bi_flags);
	else if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
		error = -EIO;

	for (i=bio->bi_idx; i<bio->bi_vcnt; i++) {
		put_page(bio->bi_io_vec[i].bv_page);
	}
	flush_bios (job->cacheblock);
	mempool_free(job, _job_pool);

	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);

	bio_put(bio);
}

static void dmcache_endio(struct bio *bio, int error) 
{
	int i = 0;

	if (error)
		clear_bit(BIO_UPTODATE, &bio->bi_flags);
	else if (!test_bit(BIO_UPTODATE, &bio->bi_flags))
		error = -EIO;

	for (i=bio->bi_idx; i<bio->bi_vcnt; i++) {
		put_page(bio->bi_io_vec[i].bv_page);
	}
	bio_put(bio);

	io_callback(error, (void *) bio->bi_private);
}

static int 
dmcache_io_async(struct bio *src_bio, int rw, sector_t sector, 
			struct block_device *where, void *context) 
{
	struct bio *clone_bio;
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;
	int i = 0, ret = 0;

	clone_bio = bio_alloc_bioset(GFP_NOIO, src_bio->bi_max_vecs, dmcache_bio_set);
	if(!clone_bio)
		printk("Errro allocating bio\n");
	

	__bio_clone(clone_bio, src_bio);
	if (bio_integrity(src_bio)) {
		printk("clone integrity\n");
		ret = bio_integrity_clone(clone_bio, src_bio, GFP_NOIO, dmcache_bio_set);
		if (ret < 0) {
			bio_put(clone_bio);
			return NULL;
		}
	}

//	clone_bio = bio_clone(src_bio, GFP_NOIO);
	for (i=src_bio->bi_idx; i<src_bio->bi_vcnt; i++) { 
		get_page(src_bio->bi_io_vec[i].bv_page);
	}

	clear_state(clone_bio->bi_rw, bio_data_dir(clone_bio));
	set_state(clone_bio->bi_rw,rw);

	clone_bio->bi_sector = sector;
	clone_bio->bi_bdev = where;
	clone_bio->bi_destructor = dmcache_destructor;
	clone_bio->bi_private = context;
	clone_bio->bi_end_io = dmcache_endio;

	DPRINTK("Submiting bio: %llu(%llu->%llu)",
	        (unsigned long long)clone_bio->bi_sector, (unsigned long long)job->src.sector, 
		(unsigned long long)sector);
	generic_make_request(clone_bio);
	return 0;
}

static int dm_io_async_bvec(unsigned int num_regions, struct dm_io_region
	*where, int rw, struct bio_vec *bvec, io_notify_fn fn, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;
	struct bio *bio = job->bio;
	struct dm_io_request iorq;

	iorq.bi_rw = (rw | (1 << 3));
	iorq.mem.type = DM_IO_BVEC;
	iorq.mem.ptr.bvec = bvec;
	iorq.notify.fn = fn;
	iorq.notify.context = context;
	iorq.client = dmc->io_client;

	DPRINTK("Send to dm_io bio: %llu(%llu->%llu,%llu)",
	        (unsigned long long)bio->bi_sector, (unsigned long long)job->src.sector, 
		(unsigned long long)job->dest.sector,(unsigned long long)job->src.count);
	return dm_io(&iorq, num_regions, where, NULL);
}

/****************************************************************************
 *  Functions and data structures for implementing a kcached to handle async
 *  I/O. Code for page and queue handling is borrowed from kcopyd.c.
 ****************************************************************************/

/*
 * Functions for handling pages used by async I/O.
 * The data asked by a bio request may not be aligned with cache blocks, in
 * which case additional pages are required for the request that is forwarded
 * to the server. A pool of pages are reserved for this purpose.
 */
static struct page_list *alloc_pl(void)
{
	struct page_list *pl;

	pl = kmalloc(sizeof(*pl), GFP_KERNEL);
	if (!pl)
		return NULL;

	pl->page = alloc_page(GFP_KERNEL);
	if (!pl->page) {
		kfree(pl);
		return NULL;
	}

	return pl;
}

static void free_pl(struct page_list *pl)
{
	__free_page(pl->page);
	kfree(pl);
}

static void drop_pages(struct page_list *pl)
{
	struct page_list *next;

	while (pl) {
		next = pl->next;
		free_pl(pl);
		pl = next;
	}
}

static int kcached_get_pages(struct cache_c *dmc, unsigned int nr,
	                         struct page_list **pages)
{
	struct page_list *pl;

	spin_lock(&dmc->lock);
	if (dmc->nr_free_pages < nr) {
		DPRINTK("kcached_get_pages: No free pages: %u<%u",
		        dmc->nr_free_pages, nr);
		spin_unlock(&dmc->lock);
		return -ENOMEM;
	}

	dmc->nr_free_pages -= nr;
	for (*pages = pl = dmc->pages; --nr; pl = pl->next)
		;

	dmc->pages = pl->next;
	pl->next = NULL;

	spin_unlock(&dmc->lock);

	return 0;
}

static void kcached_put_pages(struct cache_c *dmc, struct page_list *pl)
{
	struct page_list *cursor;

	spin_lock(&dmc->lock);
	for (cursor = pl; cursor->next; cursor = cursor->next)
		dmc->nr_free_pages++;

	dmc->nr_free_pages++;
	cursor->next = dmc->pages;
	dmc->pages = pl;

	spin_unlock(&dmc->lock);
}

static int alloc_bio_pages(struct cache_c *dmc, unsigned int nr)
{
	unsigned int i;
	struct page_list *pl = NULL, *next;

	for (i = 0; i < nr; i++) {
		next = alloc_pl();
		if (!next) {
			if (pl)
				drop_pages(pl);
			return -ENOMEM;
		}
		next->next = pl;
		pl = next;
	}

	kcached_put_pages(dmc, pl);
	dmc->nr_pages += nr;

	return 0;
}

static void free_bio_pages(struct cache_c *dmc)
{
	BUG_ON(dmc->nr_free_pages != dmc->nr_pages);
	drop_pages(dmc->pages);
	dmc->pages = NULL;
	dmc->nr_free_pages = dmc->nr_pages = 0;
}


static int jobs_init(void)
{
	_job_cache = kmem_cache_create("kcached-jobs",
	                               sizeof(struct kcached_job),
	                               __alignof__(struct kcached_job),
	                               0, NULL);
	if (!_job_cache)
		return -ENOMEM;

	_job_pool = mempool_create(MIN_JOBS, mempool_alloc_slab,
	                           mempool_free_slab, _job_cache);
	if (!_job_pool) {
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}

	return 0;
}

static void jobs_exit(void)
{
	BUG_ON(!list_empty(&_complete_jobs));
	BUG_ON(!list_empty(&_io_jobs));
	BUG_ON(!list_empty(&_pages_jobs));

	mempool_destroy(_job_pool);
	kmem_cache_destroy(_job_cache);
	_job_pool = NULL;
	_job_cache = NULL;
}

/*
 * Functions to push and pop a job onto the head of a given job list.
 */
static inline struct kcached_job *pop(struct list_head *jobs)
{
	struct kcached_job *job = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);

	if (!list_empty(jobs)) {
		job = list_entry(jobs->next, struct kcached_job, list);
		list_del(&job->list);
	}
	spin_unlock_irqrestore(&_job_lock, flags);

	return job;
}

static inline void push(struct list_head *jobs, struct kcached_job *job)
{
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	list_add_tail(&job->list, jobs);
	spin_unlock_irqrestore(&_job_lock, flags);
}


/****************************************************************************
 * Functions for asynchronously fetching data from source device and storing
 * data in cache device. Because the requested data may not align with the
 * cache blocks, extra handling is required to pad a block request and extract
 * the requested data from the results.
 ****************************************************************************/

static void io_callback(unsigned long error, void *context)
{
	struct kcached_job *job = (struct kcached_job *) context;
	struct bio *bio = job->bio, *clone_bio;
	int i =0;

	if (error) {
		/* TODO */
		DMERR("io_callback: io error");
		return;
	}

	if (job->rw == READ) {
		job->rw = WRITE;
		push(&_io_jobs, job);
	} else 
		push(&_complete_jobs, job);
	wake();
}

/*
 * Fetch data from the source device asynchronously.
 * For a READ bio, if a cache block is larger than the requested data, then
 * additional data are prefetched. Larger cache block size enables more
 * aggressive read prefetching, which is useful for read-mostly usage.
 * For a WRITE bio, if a cache block is larger than the requested data, the
 * entire block needs to be fetched, and larger block size incurs more overhead.
 * In scenaros where writes are frequent, 4KB is a good cache block size.
 */
static int do_fetch(struct kcached_job *job)
{
	int r = 0, i, j;
	struct bio *bio = job->bio;
	struct cache_c *dmc = job->dmc;
	unsigned int offset, head, tail, remaining, nr_vecs, idx = 0;
	struct bio_vec *bvec;
	struct page_list *pl;

	offset = (unsigned int) (bio->bi_sector & dmc->block_mask);
	head = to_bytes(offset);
	tail = to_bytes(dmc->block_size) - bio->bi_size - head;

	DPRINTK("do_fetch: %llu(%llu->%llu,%llu), head:%u,tail:%u",
	        (unsigned long long)bio->bi_sector, (unsigned long long)job->src.sector, 
		(unsigned long long)job->dest.sector,
	        (unsigned long long)job->src.count, (unsigned)head, (unsigned)tail);

	if (bio_data_dir(bio) == READ) { /* The original request is a READ */
		if (0 == job->nr_pages) { /* The request is aligned to cache block */
//			r = dm_io_async_bvec(1, &job->src, READ,
//			                     bio->bi_io_vec + bio->bi_idx, io_callback, job);
			r = dmcache_io_async(bio,  READ, job->src.sector, job->src.bdev, job);
		
			return r;
		}

		nr_vecs = bio->bi_vcnt - bio->bi_idx + job->nr_pages;
		bvec = kmalloc(nr_vecs * sizeof(*bvec), GFP_NOIO);
		if (!bvec) {
			DMERR("do_fetch: No memory");
			return 1;
		}

		pl = job->pages;
		i = 0;
		while (head) {
			bvec[i].bv_len = min(head, (unsigned int)PAGE_SIZE);
			bvec[i].bv_offset = 0;
			bvec[i].bv_page = pl->page;
			head -= bvec[i].bv_len;
			pl = pl->next;
			i++;
		}

		remaining = bio->bi_size;
		j = bio->bi_idx;
		while (remaining) {
			bvec[i] = bio->bi_io_vec[j];
			remaining -= bvec[i].bv_len;
			i++; j++;
		}

		while (tail) {
			bvec[i].bv_len = min(tail, (unsigned int)PAGE_SIZE);
			bvec[i].bv_offset = 0;
			bvec[i].bv_page = pl->page;
			tail -= bvec[i].bv_len;
			pl = pl->next;
			i++;
		}

		job->bvec = bvec;
		r = dm_io_async_bvec(1, &job->src, READ, job->bvec, io_callback, job);
		return r;
	} else { /* The original request is a WRITE */
		pl = job->pages;

		if (head && tail) { /* Special case */
			bvec = kmalloc(job->nr_pages * sizeof(*bvec), GFP_KERNEL);
			if (!bvec) {
				DMERR("do_fetch: No memory");
				return 1;
			}
			for (i=0; i<job->nr_pages; i++) {
				bvec[i].bv_len = PAGE_SIZE;
				bvec[i].bv_offset = 0;
				bvec[i].bv_page = pl->page;
				pl = pl->next;
			}
			job->bvec = bvec;
			r = dm_io_async_bvec(1, &job->src, READ, job->bvec,
			                     io_callback, job);
			return r;
		}

		bvec = kmalloc((job->nr_pages + bio->bi_vcnt - bio->bi_idx)
				* sizeof(*bvec), GFP_KERNEL);
		if (!bvec) {
			DMERR("do_fetch: No memory");
			return 1;
		}

		i = 0;
		while (head) {
			bvec[i].bv_len = min(head, (unsigned int)PAGE_SIZE);
			bvec[i].bv_offset = 0;
			bvec[i].bv_page = pl->page;
			head -= bvec[i].bv_len;
			pl = pl->next;
			i++;
		}

		remaining = bio->bi_size;
		j = bio->bi_idx;
		while (remaining) {
			bvec[i] = bio->bi_io_vec[j];
			remaining -= bvec[i].bv_len;
			i++; j++;
		}

		if (tail) {
			idx = i;
			bvec[i].bv_offset = (to_bytes(offset) + bio->bi_size) &
			                    (PAGE_SIZE - 1);
			bvec[i].bv_len = PAGE_SIZE - bvec[i].bv_offset;
			bvec[i].bv_page = pl->page;
			tail -= bvec[i].bv_len;
			pl = pl->next; i++;
			while (tail) {
				bvec[i].bv_len = PAGE_SIZE;
				bvec[i].bv_offset = 0;
				bvec[i].bv_page = pl->page;
				tail -= bvec[i].bv_len;
				pl = pl->next; i++;
			}
		}

		job->bvec = bvec;
		r = dm_io_async_bvec(1, &job->src, READ, job->bvec + idx,
		                     io_callback, job);

		return r;
	}
}

/*
 * Store data to the cache source device asynchronously.
 * For a READ bio request, the data fetched from the source device are returned
 * to kernel and stored in cache at the same time.
 * For a WRITE bio request, the data are written to the cache and source device
 * at the same time.
 */
static int do_store(struct kcached_job *job)
{
	int i, j, r = 0;
	int loop;
	struct bio *bio = job->bio, *clone;
	struct cache_c *dmc = job->dmc;
	unsigned int offset, head, tail, remaining, nr_vecs;
	struct bio_vec *bvec;
	unsigned char * fingerprint;
	struct fingerprint_store * fingerprint_store;
	struct reverse_node * reverse_node;
	struct cacheblock * moved_cacheblock;
	struct source_tracker * source_tracker;
	unsigned long err;

	dmc->potential++;

	offset = (unsigned int) (bio->bi_sector & dmc->block_mask);
	head = to_bytes(offset);
	tail = to_bytes(dmc->block_size) - bio->bi_size - head;

	/*DPRINTK("do_store: %llu(%llu->%llu,%llu), head:%u,tail:%u",
	        (unsigned long long)bio->bi_sector, (unsigned long long)job->src.sector, 
		(unsigned long long)job->dest.sector,(unsigned long long)job->src.count, 
		(unsigned)head, (unsigned)tail);*/

	if (bio_data_dir(bio) == READ) {
		clone = bio_clone(bio, GFP_NOIO);
		for (i=bio->bi_idx; i<bio->bi_vcnt; i++) {
			get_page(bio->bi_io_vec[i].bv_page);
		}
		DPRINTK("bio ended for %llu:%u", bio->bi_sector, bio->bi_size);
		bio_endio(bio, 0);
		bio = clone;
		job->bio = clone;
	}

	//begin

	if(DEDUP > 0 && bio->bi_size >= (dmc->block_size * sector_size))
	{
		printk("----------------------------------------------------------------\n");
		printk("Starting do_store\n");
		fingerprint = kmalloc(sizeof(*fingerprint) * 16, GFP_KERNEL);
		make_fingerprint(bio, fingerprint, dmc->block_size);
		printk("Fingerprint: ");

		for(loop = 0; loop < 16; loop++)
		{
			printk("%02x", fingerprint[loop]);
		}

		printk("\n");

		//fingerprint_store = find_fingerprint(fingerprint_tree, fingerprint);
		fingerprint_store = find_fingerprint(fingerprint_table, fingerprint, dmc->size);

		if(fingerprint_store == NULL)
		{
			printk("No matching fingerprint found\n");
			//add_fingerprint(fingerprint_tree, fingerprint, job->dest.sector >> dmc->block_shift);
			add_fingerprint(fingerprint_table, fingerprint, job->dest.sector >> dmc->block_shift, dmc->size);

			if (bio_data_dir(bio) == READ)
			{
				add_duplicate(duplicate_tree, get_block_index(job->src.sector, job->cacheblock->disk), job->cacheblock->disk, job->src.sector, job->dest.sector >> dmc->block_shift, FALSE);
				reverse_node = create_reverse_node(job->dest.sector >> dmc->block_shift, 1, fingerprint, 0);
				source_tracker = create_source_tracker(get_block_index(job->src.sector, job->cacheblock->disk), 0);
				add_source_tracker(reverse_node, source_tracker);
				add_reverse(reverse_tree, reverse_node);
			}
			else
			{
				add_duplicate(duplicate_tree, get_block_index(job->src.sector, job->cacheblock->disk), job->cacheblock->disk, job->src.sector, job->dest.sector >> dmc->block_shift, TRUE);
				reverse_node = create_reverse_node(job->dest.sector >> dmc->block_shift, 1, fingerprint, 1);
				source_tracker = create_source_tracker(get_block_index(job->src.sector, job->cacheblock->disk), 1);
				add_source_tracker(reverse_node, source_tracker);
				add_reverse(reverse_tree, reverse_node);
			}	

			printk("----------------------------------------------------------------\n");
		}
		else
		{
			printk("Matching fingerprint found with cache = %llu\n", fingerprint_store->cacheblock);
			printk("Details, source = %llu, disk = %d, index = %llu\n", job->src.sector, job->cacheblock->disk, get_block_index(job->src.sector, job->cacheblock->disk));

			reverse_node = find_reverse(reverse_tree, fingerprint_store->cacheblock);
			reverse_node->count++;
			printk("Reverse node count: %d\n", reverse_node->count);

			if (bio_data_dir(bio) == READ)
			{
				add_duplicate(duplicate_tree, get_block_index(job->src.sector, job->cacheblock->disk), job->cacheblock->disk, job->src.sector, fingerprint_store->cacheblock, FALSE);
				source_tracker = create_source_tracker(get_block_index(job->src.sector, job->cacheblock->disk), 0);
				add_source_tracker(reverse_node, source_tracker);
			}
			else
			{
				add_duplicate(duplicate_tree, get_block_index(job->src.sector, job->cacheblock->disk), job->cacheblock->disk, job->src.sector, fingerprint_store->cacheblock, TRUE);
				source_tracker = create_source_tracker(get_block_index(job->src.sector, job->cacheblock->disk), 1);
				add_source_tracker(reverse_node, source_tracker);
				reverse_node->dirty_count++;
			}

			if (is_state(dmc->blocks[reverse_node->cacheblock].state, VALID) && bio_data_dir(bio) == WRITE)
			{
				printk("Making the cache dirty\n");
				set_state(dmc->blocks[reverse_node->cacheblock].state, DIRTY);
				dmc->dirty_blocks++;
				virtual_mapping[dmc->blocks[reverse_node->cacheblock].disk].dirty_blocks++;
			}

			cache_invalidate(dmc, job->cacheblock);
			printk("----------------------------------------------------------------\n");
			io_callback(err, job);
                	return 0;
		}
	}

	//end

	dmc->actual++;
	
	if (0 == job->nr_pages){ /* Original request is aligned with cache blocks */
//		r = dm_io_async_bvec(1, &job->dest, WRITE, bio->bi_io_vec + bio->bi_idx,
//		                     io_callback, job);
//		printk("do_store\n");
		r = dmcache_io_async(bio,  WRITE, job->dest.sector, job->dest.bdev, job);
	}else {
		if (bio_data_dir(bio) == WRITE && head > 0 && tail > 0) {
			DPRINTK("Special case: %lu %u %u", bio_data_dir(bio), head, tail);
			nr_vecs = job->nr_pages + bio->bi_vcnt - bio->bi_idx;
			if (offset && (offset + bio->bi_size < PAGE_SIZE)) nr_vecs++;
			DPRINTK("Create %u new vecs", nr_vecs);
			bvec = kmalloc(nr_vecs * sizeof(*bvec), GFP_KERNEL);
			if (!bvec) {
				DMERR("do_store: No memory");
			return 1;
			}

			i = 0;
			while (head) {
				bvec[i].bv_len = min(head, job->bvec[i].bv_len);
				bvec[i].bv_offset = 0;
				bvec[i].bv_page = job->bvec[i].bv_page;
				head -= bvec[i].bv_len;
				i++;
			}
			remaining = bio->bi_size;
			j = bio->bi_idx;
			while (remaining) {
				bvec[i] = bio->bi_io_vec[j];
				remaining -= bvec[i].bv_len;
				i++; j++;
			}
			j = (to_bytes(offset) + bio->bi_size) / PAGE_SIZE;
			bvec[i].bv_offset = (to_bytes(offset) + bio->bi_size) -
			                    j * PAGE_SIZE;
			bvec[i].bv_len = PAGE_SIZE - bvec[i].bv_offset;
			bvec[i].bv_page = job->bvec[j].bv_page;
			tail -= bvec[i].bv_len;
			i++; j++;
			while (tail) {
				bvec[i] = job->bvec[j];
				tail -= bvec[i].bv_len;
				i++; j++;
			}
			kfree(job->bvec);
			job->bvec = bvec;
		}

		//r = dmcache_io_async(bio,  WRITE, job->dest.sector, job->dest.bdev, job);
		r = dm_io_async_bvec(1, &job->dest, WRITE, job->bvec, io_callback, job);
	}
	return r;
}

static int do_io(struct kcached_job *job)
{
	int r = 0;

	if (job->rw == READ) { /* Read from source device */
		r = do_fetch(job);
	} else { /* Write to cache device */
		r = do_store(job);
	}

	return r;
}

static int do_pages(struct kcached_job *job)
{
	int r = 0;

	r = kcached_get_pages(job->dmc, job->nr_pages, &job->pages);

	if (r == -ENOMEM) /* can't complete now */
		return 1;

	/* this job is ready for io */
	push(&_io_jobs, job);
	return 0;
}

/*
 * Flush the bios that are waiting for this cache insertion or write back.
 */
static void flush_bios(struct cacheblock *cacheblock)
{
        struct cache_c *dmc = shared_cache;
	struct bio *bio;
	struct bio *n;
	struct reverse_node * reverse_node;

	bio = bio_list_get(&cacheblock->bios);
	if (is_state(cacheblock->state, WRITEBACK)) { /* Write back finished */

		if(DEDUP > 0)
		{
			reverse_node = find_reverse(reverse_tree, cacheblock->cacheblock);
			reverse_node->dirty_count--;

			if(reverse_node->dirty_count > 0)
			{
				return;
			}
		}

		spin_lock(&cacheblock->lock);
		cacheblock->state = VALID;
		spin_unlock(&cacheblock->lock);
	} else if (is_state(cacheblock->state, WRITETHROUGH)) { 
		cache_invalidate(dmc, cacheblock);
	} else { /* Cache insertion finished */
		spin_lock(&cacheblock->lock);
		set_state(cacheblock->state, VALID);
		clear_state(cacheblock->state, RESERVED);
		spin_unlock(&cacheblock->lock);
	}

	while (bio) {
		n = bio->bi_next;
		bio->bi_next = NULL;
		DPRINTK("Flush bio: %llu->%llu (%u bytes)",
		        (unsigned long long)cacheblock->block, (unsigned long long)bio->bi_sector, 
			(unsigned)bio->bi_size);
		generic_make_request(bio);
		bio = n;
	}
}

static int do_allocate(struct kcached_job *job)
{
	struct bio *bio = job->bio;

	bio->bi_sector = job->src.sector;
	bio->bi_bdev = job->src.bdev;
	bio->bi_destructor = dmcache_destructor;
	bio->bi_end_io = nocallback_endio;
	bio->bi_private = job;
	//set_state(job->cacheblock->state, WRITEBACK);

	generic_make_request(bio);
	return 0;
}

static int do_complete(struct kcached_job *job)
{
	int i = 0;
	struct bio *bio = job->bio;
	struct cache_c *dmc = shared_cache;
	struct bio  *clone_bio;

	DPRINTK("do_complete: %llu", (unsigned long long)bio->bi_sector);
	if (bio_data_dir(bio) == READ) {
		for (i=bio->bi_idx; i<bio->bi_vcnt; i++) {
			put_page(bio->bi_io_vec[i].bv_page);
		}
		bio_put(bio);
	} else{
		if (job->allocate == 1 && job->rw == WRITE) {
			clone_bio = bio_alloc_bioset(GFP_NOIO, bio->bi_max_vecs, dmcache_bio_set);
			if(!clone_bio)
				printk("Errro allocating bio\n");

			__bio_clone(clone_bio, bio);
			for (i=bio->bi_idx; i<bio->bi_vcnt; i++) { 
				get_page(bio->bi_io_vec[i].bv_page);
			}
		}
		bio_endio(bio, 0);
	}
	if (job->nr_pages > 0) {
		kfree(job->bvec);
		kcached_put_pages(job->dmc, job->pages);
	}

	flush_bios(job->cacheblock);
	if (job->allocate == 1 && job->rw == WRITE) {
		job->bio = clone_bio;

		push(&_allocate_jobs, job);
		queue_work(_kallocate_wq, &_kallocate_work);
		return 0;
	}

	mempool_free(job, _job_pool);

	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);

	return 0 ;
}

/*
 * Run through a list for as long as possible.  Returns the count
 * of successful jobs.
 */
static int process_jobs(struct list_head *jobs,
	                    int (*fn) (struct kcached_job *))
{
	struct kcached_job *job;
	int r, count = 0;

	while ((job = pop(jobs))) {
		r = fn(job);

		if (r < 0) {
			/* error this rogue job */
			DMERR("process_jobs: Job processing error");
		}

		if (r > 0) {
			/*
			 * We couldn't service this job ATM, so
			 * push this job back onto the list.
			 */
			push(jobs, job);
			break;
		}

		count++;
	}

	return count;
}

static void do_work(struct work_struct *ignored)
{
	process_jobs(&_complete_jobs, do_complete);
	process_jobs(&_pages_jobs, do_pages);
	process_jobs(&_io_jobs, do_io);
}
static void do_work_allocate(struct work_struct *ignored)
{
	process_jobs(&_allocate_jobs, do_allocate);
}


static void queue_job(struct kcached_job *job)
{
	atomic_inc(&job->dmc->nr_jobs);
	if (job->nr_pages > 0) /* Request pages */
		push(&_pages_jobs, job);
	else /* Go ahead to do I/O */
		push(&_io_jobs, job);
	wake();
}

static int kcached_init(struct cache_c *dmc)
{
	int r;

	spin_lock_init(&dmc->lock);
        sema_init(&dmc->lru_mutex, 1);

	dmc->pages = NULL;
	dmc->nr_pages = dmc->nr_free_pages = 0;
	r = alloc_bio_pages(dmc, DMCACHE_COPY_PAGES);
	if (r) {
		DMERR("kcached_init: Could not allocate bio pages");
		return r;
	}

	init_waitqueue_head(&dmc->destroyq);
	init_waitqueue_head(&dmc->wait_writeback);
	atomic_set(&dmc->nr_jobs, 0);

	return 0;
}

void kcached_client_destroy(struct cache_c *dmc)
{
	/* Wait for completion of all jobs submitted by this client. */
	wait_event(dmc->destroyq, !atomic_read(&dmc->nr_jobs));

	free_bio_pages(dmc);
}


/****************************************************************************
 * Functions for writing back dirty blocks.
 * We leverage kcopyd to write back dirty blocks because it is convenient to
 * use and it is not reasonble to reimplement the same function here. But we
 * need to reserve pages for both kcached and kcopyd. TODO: dynamically change
 * the number of reserved pages.
 ****************************************************************************/

static void copy_callback(int read_err, unsigned int write_err, void *context)
{
        struct cache_c *dmc = shared_cache;
	struct cacheblock *cacheblock = (struct cacheblock *) context;
	flush_bios(cacheblock);

	virtual_mapping[cacheblock->disk].dirty_blocks--;
	if (virtual_mapping[cacheblock->disk].dirty_blocks == 0) {
		DPRINTK("Dirty gone!!!!!");
		wake_up(&dmc->wait_writeback);
	}else{
		DPRINTK("still dirty!!!");
	}
}

static void copy_block(struct cache_c *dmc, struct dm_io_region src,
	                   struct dm_io_region dest, struct cacheblock *cacheblock)
{
	DPRINTK("Copying: %llu:%llu->%llu:%llu",
			(unsigned long long)src.sector, (unsigned long long)src.count * 512, 
			(unsigned long long)dest.sector, (unsigned long long)dest.count * 512);
	dm_kcopyd_copy(dmc->kcp_client, &src, 1, &dest, 0, (dm_kcopyd_notify_fn) copy_callback, cacheblock);
}

static void write_back(struct cache_c *dmc, struct cacheblock *cache, unsigned int length)
{
	struct dm_io_region src, dest;
	struct cacheblock *writecache;
	unsigned int i;

	DPRINTK("Write back block (%llu, %u)",
	        (unsigned long long)cache->cacheblock, (unsigned)length);
	src.bdev = dmc->cache_dev->bdev;
	src.sector = cache->cacheblock << dmc->block_shift;
	src.count = dmc->block_size * length;
	dest.bdev= virtual_mapping[cache->disk].src_dev->bdev;
	dest.sector = cache->block;
	dest.count = dmc->block_size * length;

/*
        for (i=0; i<length; i++)
        {
                writecache = radix_tree_lookup(dmc->cache, get_block_index((cache->block)+i,cache->disk));
                if(writecache != NULL){
                        set_state(writecache->state, WRITEBACK);
                }
        }
*/
	set_state(cache->state, WRITEBACK);
        dmc->dirty_blocks -= length;
        copy_block(dmc, src, dest, cache);
}

static void write_back_mod(struct cache_c *dmc, struct cacheblock *cache, unsigned int length, sector_t real_dest, int real_disk)
{
	struct dm_io_region src, dest;
	struct cacheblock *writecache;
	unsigned int i;

	DPRINTK("Write back block (%llu, %u)",
	        (unsigned long long)cache->cacheblock, (unsigned)length);
	src.bdev = dmc->cache_dev->bdev;
	src.sector = cache->cacheblock << dmc->block_shift;
	src.count = dmc->block_size * length;
	dest.bdev= virtual_mapping[real_disk].src_dev->bdev;
	dest.sector = real_dest;
	dest.count = dmc->block_size * length;

/*
        for (i=0; i<length; i++)
        {
                writecache = radix_tree_lookup(dmc->cache, get_block_index((cache->block)+i,cache->disk));
                if(writecache != NULL){
                        set_state(writecache->state, WRITEBACK);
                }
        }
*/
	set_state(cache->state, WRITEBACK);
        dmc->dirty_blocks -= length;
        copy_block(dmc, src, dest, cache);
}


/****************************************************************************
 *  Functions for implementing the various cache operations.
 ****************************************************************************/
static sector_t get_block_index(sector_t block, int disk){
        return ( block + virtual_mapping[disk].dev_offset);
	DPRINTK("Free to destroy: %d",cnt_active_map);
}

/*
 * Insert a block into the cache (in the frame specified by cache_block).
 */
static int cache_insert(struct cache_c *dmc, sector_t block,
                            struct cacheblock *cache, int disk)
{
        dmc->inserts++;
        virtual_mapping[disk].inserts++;

        spin_lock(&cache->lock);
        set_state(cache->state, RESERVED);
        spin_unlock(&cache->lock);

        cache->disk = disk;
        cache->block = block;

        radix_tree_insert(dmc->cache, get_block_index(block,disk), (void *) cache);
//        spin_unlock(&cache->lock);

        return 1;
}

/*
 * Invalidate a block (specified by cache_block) in the cache.
 */
static void cache_invalidate(struct cache_c *dmc, struct cacheblock *cache)
{
//        DPRINTK("Cache invalidate: Block %llu(%llu)",
//                (unsigned long long)cache->cacheblock, (unsigned long long)cache->block);

	struct reverse_node * reverse_node;

	if(DEDUP > 0)
	{
		reverse_node = find_reverse(reverse_tree, cache->cacheblock);

		if(reverse_node != NULL && reverse_node->count > 0)
		{
			remove_all(duplicate_tree, reverse_node);
			//remove_fingerprint(fingerprint_tree, reverse_node->fingerprint);
			remove_fingerprint(fingerprint_table, reverse_node->fingerprint, dmc->size);
			remove_reverse(reverse_tree, cache->cacheblock);
		}
	}

 	spin_lock(&cache->lock);
        cache->state = INVALID;
	spin_unlock(&cache->lock);

        radix_tree_delete(dmc->cache, get_block_index(cache->block,cache->disk));
}

/*
 * Handle a cache hit:
 *  For READ, serve the request from cache is the block is ready; otherwise,
 *  queue the request for later processing.
 *  For write, invalidate the cache block if write-through. If write-back,
 *  serve the request from cache if the block is ready, or queue the request
 *  for later processing if otherwise.
 */
static int cache_hit(struct cache_c *dmc, struct bio* bio, struct cacheblock *cache)
{
	unsigned int offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
        sector_t cache_block = cache->cacheblock;
        down(&dmc->lru_mutex);
        list_move_tail(&cache->list, dmc->lru);
        up(&dmc->lru_mutex);

        DPRINTK("HIT: cacheblock:%llu Block: %llu Disk:%d", 
		(unsigned long long)cache->cacheblock, 
		(unsigned long long)cache->block,cache->disk);

	dmc->cache_hits++;
        virtual_mapping[cache->disk].cache_hits++;

        if (bio_data_dir(bio) == READ) { /* READ hit */
                dmc->read_hits++;
                virtual_mapping[cache->disk].read_hits++;

                bio->bi_bdev = dmc->cache_dev->bdev;
                bio->bi_sector = (cache_block << dmc->block_shift)  + offset;

                spin_lock(&cache->lock);

                if (is_state(cache->state, VALID)) { /* Valid cache block */
                        spin_unlock(&cache->lock);
                        return 1;
                }

                /* Cache block is not ready yet */
                DPRINTK("Add to bio list %s(%llu)",
                                dmc->cache_dev->name, (unsigned long long)bio->bi_sector);
                bio_list_add(&cache->bios, bio);

                spin_unlock(&cache->lock);
                return 0;
	} else { /* WRITE hit */
                dmc->invalidates++;
                virtual_mapping[cache->disk].invalidates++;

		if (dmc->write_policy == WRITE_THROUGH) { /* Invalidate cached data */
			bio->bi_bdev = virtual_mapping[cache->disk].src_dev->bdev;
			if (is_state(cache->state, VALID)) {
				cache_invalidate(dmc, cache);
				return 1;
			}
			set_state(cache->state,WRITETHROUGH);
			bio_list_add(&cache->bios, bio);
			return 0;
		}

		if (dmc->write_policy == WRITE_ALLOCATE) { 
                	return cache_write_miss(dmc, bio, cache->disk, cache);
		/*	if (is_state(cache->state, VALID) ||
				is_state(cache->state, INVALID) ) {
                		return cache_write_miss(dmc, bio, cache->disk, cache);
			}
			set_state(cache->state,WRITEALLOCATE);
			bio_list_add(&cache->bios, bio);
			return 0;*/
		}
		
                /* Write delay */
                if (!is_state(cache->state, DIRTY)) {
                        set_state(cache->state, DIRTY);
                        dmc->dirty_blocks++;
			virtual_mapping[cache->disk].dirty_blocks++;
                }

                spin_lock(&cache->lock);

                /* In the middle of write back */
                if (is_state(cache->state, WRITEBACK)) {
                        /* Delay this write until the block is written back */
                        bio->bi_bdev = virtual_mapping[cache->disk].src_dev->bdev;
                        DPRINTK("Add to bio list %s(%llu)",
                                        virtual_mapping[cache->disk].src_dev->name,
                                        (long long unsigned int)bio->bi_sector);
                        bio_list_add(&cache->bios, bio);
                        spin_unlock(&cache->lock);
                        return 0;
                }

                /* Cache block not ready yet */
                if (is_state(cache->state, RESERVED)) {
                        bio->bi_bdev = dmc->cache_dev->bdev;
                        bio->bi_sector = (cache_block << dmc->block_shift) + offset;
                        DPRINTK("Add to bio list %s(%llu)",
                                        dmc->cache_dev->name, (unsigned long long)bio->bi_sector);
                        bio_list_add(&cache->bios, bio);
                        spin_unlock(&cache->lock);
                        return 0;
                }

                /* Serve the request from cache */
                bio->bi_bdev = dmc->cache_dev->bdev;
                bio->bi_sector = (cache_block << dmc->block_shift) + offset;

                spin_unlock(&cache->lock);
                return 1;

	}
}


static struct kcached_job *new_kcached_job(struct cache_c *dmc, struct bio* bio,
	                                       sector_t request_block,
                                           struct cacheblock *cache)
{
	struct dm_io_region src, dest;
	struct kcached_job *job;

	src.bdev = virtual_mapping[cache->disk].src_dev->bdev; ;
	src.sector = request_block;
	src.count = dmc->block_size;
	dest.bdev = dmc->cache_dev->bdev;
	dest.sector = cache->cacheblock << dmc->block_shift;
	dest.count = src.count;

	job = mempool_alloc(_job_pool, GFP_NOIO);
	job->dmc = dmc;
	job->bio = bio;
	job->src = src;
	job->dest = dest;
	job->cacheblock = cache;
	job->allocate = 0;

	return job;
}

static struct cacheblock* request_cache_block(struct cache_c *dmc, int disk)
{
	struct cacheblock *cache = NULL;
	struct v_map *map_dev = &virtual_mapping[disk];
	struct list_head *temp;
	struct source_tracker * post;
	struct source_tracker * n;
	struct source_tracker * tmp;
	struct reverse_node * reverse_node;
	struct duplicate_node * duplicate_node;
	int res = -1;

	//Take item from empty List
	if(dmc->allocate < dmc->size) {
		dmc->allocate++;
		map_dev->allocate++;

		down(&dmc->lru_mutex);
		cache = list_first_entry(dmc->lru, struct cacheblock, list);
		list_move_tail(&cache->list, dmc->lru);
		up(&dmc->lru_mutex);
		res = 1;
		DPRINTK("DM_REQUEST: Taking cacheblock from Global empty LRU");
	} else{
		// Below its limit
		if (map_dev->allocate < map_dev->limit) {
			down(&dmc->lru_mutex);
			list_for_each( temp, dmc->lru ){
				cache = list_first_entry(dmc->lru, struct cacheblock, list);
				if(!is_state(cache->state, DIRTY)){
					list_move_tail(&cache->list, dmc->lru);
					if (cache->disk != disk){
						map_dev->allocate++;
						virtual_mapping[cache->disk].allocate--;
					}
					res = 1;
					break;
				}
			}
			up(&dmc->lru_mutex);
			DPRINTK("DM_REQUEST: Taking cacheblock from different VM:%d LRU",cache->disk);
			// Above is limit
		} else {
			down(&dmc->lru_mutex);
			list_for_each( temp, dmc->lru ){
				cache = list_entry(temp, struct cacheblock, list);
				if(!is_state(cache->state, DIRTY) && cache->disk == disk){
					list_move_tail(&cache->list, dmc->lru);
					if (cache->disk != disk){
						map_dev->allocate++;
						virtual_mapping[cache->disk].allocate--;
					}
					res = 1;
					break;
				}
			}
			up(&dmc->lru_mutex);
			DPRINTK("DM_REQUEST: Taking cacheblock from self VM:%d LRU",disk);
		}
	}
	if (res  == -1) //All cache is dirty!!
	{
		cache_flush(dmc,-1);
	
		//  FIXME!!!!
		 //  Take Least block just to server this one
		 //

		if(DEDUP > 0)
		{
			reverse_node = find_reverse(reverse_tree, cache->cacheblock);		
				
			if(reverse_node != NULL)
			{
				post = NULL;
				n = NULL;
				tmp = NULL;

				list_for_each_entry_safe(post, n, &reverse_node->first, list)
				{
					tmp = list_entry(&post->list, struct source_tracker, list);

					if(tmp->dirty == TRUE)
					{
						duplicate_node = find_duplicate(duplicate_tree, tmp->block_index);
						write_back_mod(dmc,cache,1, duplicate_node->sourceblock, duplicate_node->device_id);
						tmp->dirty = FALSE;
					}
				}

				//testing
				//write_back(dmc, cache, 1);
			}
			else
			{
				write_back(dmc,cache,1);
			}
		}
		else
		{
			write_back(dmc,cache,1);
		}

		//write_back(dmc,cache,1);
		down(&dmc->lru_mutex);
		cache = list_first_entry(dmc->lru, struct cacheblock, list);
		list_move_tail(&cache->list, dmc->lru);
		up(&dmc->lru_mutex);
	}

	return cache;
}

static struct cacheblock* request_cache_block_dedup(struct cache_c *dmc, int disk)
{
	struct cacheblock *cache = NULL;
	struct cacheblock * previous_cache = NULL;
	struct v_map *map_dev = &virtual_mapping[disk];
	struct list_head *temp;
	struct source_tracker * post;
	struct source_tracker * n;
	struct source_tracker * tmp;
	struct reverse_node * reverse_node_cache;
	struct reverse_node * reverse_node_prev;
	struct reverse_node * reverse_node;
	struct duplicate_node * duplicate_node;
	int res = -1;

	//Take item from empty List
	if(dmc->allocate < dmc->size) {
		dmc->allocate++;
		map_dev->allocate++;

		down(&dmc->lru_mutex);
		cache = list_first_entry(dmc->lru, struct cacheblock, list);
		list_move_tail(&cache->list, dmc->lru);
		up(&dmc->lru_mutex);
		res = 1;
		DPRINTK("DM_REQUEST: Taking cacheblock from Global empty LRU");
	} else{
		// Below its limit
		if (map_dev->allocate < map_dev->limit) {
			down(&dmc->lru_mutex);
			list_for_each( temp, dmc->lru ){
				cache = list_first_entry(dmc->lru, struct cacheblock, list);
				if(!is_state(cache->state, DIRTY)){
					list_move_tail(&cache->list, dmc->lru);
					if (cache->disk != disk){
						map_dev->allocate++;
						virtual_mapping[cache->disk].allocate--;
					}
					res = 1;
					//break;

					if(previous_cache != NULL)
					{
						reverse_node_cache = find_reverse(reverse_tree, cache->cacheblock);
						reverse_node_prev = find_reverse(reverse_tree, previous_cache->cacheblock);

						if(reverse_node_cache->count < reverse_node_prev->count)
						{
							cache = previous_cache;
						}
					}

					previous_cache = cache;
				}
			}
			up(&dmc->lru_mutex);
			DPRINTK("DM_REQUEST: Taking cacheblock from different VM:%d LRU",cache->disk);
			// Above is limit
		} else {
			down(&dmc->lru_mutex);
			list_for_each( temp, dmc->lru ){
				cache = list_entry(temp, struct cacheblock, list);
				if(!is_state(cache->state, DIRTY) && cache->disk == disk){
					list_move_tail(&cache->list, dmc->lru);
					if (cache->disk != disk){
						map_dev->allocate++;
						virtual_mapping[cache->disk].allocate--;
					}
					res = 1;
					//break;

					if(previous_cache != NULL)
					{
						reverse_node_cache = find_reverse(reverse_tree, cache->cacheblock);
						reverse_node_prev = find_reverse(reverse_tree, previous_cache->cacheblock);

						if(reverse_node_cache->count < reverse_node_prev->count)
						{
							cache = previous_cache;
						}
					}

					previous_cache = cache;
				}
			}
			up(&dmc->lru_mutex);
			DPRINTK("DM_REQUEST: Taking cacheblock from self VM:%d LRU",disk);
		}
	}
	if (res  == -1) //All cache is dirty!!
	{
		cache_flush(dmc,-1);
	
		//  FIXME!!!!
		 //  Take Least block just to server this one
		 //

		if(DEDUP > 0)
		{
			reverse_node = find_reverse(reverse_tree, cache->cacheblock);		
				
			if(reverse_node != NULL)
			{
				post = NULL;
				n = NULL;
				tmp = NULL;

				list_for_each_entry_safe(post, n, &reverse_node->first, list)
				{
					tmp = list_entry(&post->list, struct source_tracker, list);

					if(tmp->dirty == TRUE)
					{
						duplicate_node = find_duplicate(duplicate_tree, tmp->block_index);
						write_back_mod(dmc,cache,1, duplicate_node->sourceblock, duplicate_node->device_id);
						tmp->dirty = FALSE;
					}
				}

				//testing
				//write_back(dmc, cache, 1);
			}
			else
			{
				write_back(dmc,cache,1);
			}
		}
		else
		{
			write_back(dmc,cache,1);
		}

		//write_back(dmc,cache,1);
		down(&dmc->lru_mutex);
		cache = list_first_entry(dmc->lru, struct cacheblock, list);
		list_move_tail(&cache->list, dmc->lru);
		up(&dmc->lru_mutex);
	}

	return cache;
}



/*
 * Handle a read cache miss:
 *  Update the metadata; fetch the necessary block from source device;
 *  store data to cache device.
 */
static int cache_read_miss(struct cache_c *dmc, struct bio* bio, int disk) {
        struct cacheblock *cache;
        unsigned int offset, head, tail;
        struct kcached_job *job;
        sector_t request_block, left;

        offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
        request_block = bio->bi_sector - offset;


	cache = request_cache_block(dmc,disk);

        if(is_state(cache->state, RESERVED) || is_state(cache->state, WRITEBACK )) {
                DPRINTK("Got a spot RESERVED cacheblock: %llu val:%d ",
                                (unsigned long long)cache->cacheblock,cache->state);
                DPRINTK("Add to bio list %s(%llu)",
                                dmc->cache_dev->name, (unsigned long long)bio->bi_sector);
                bio_list_add(&cache->bios, bio);
                return 0;
        }

        if (is_state(cache->state, VALID)) {
                DPRINTK("Replacing Block:%llu Cache Block: %llu To:%llu Disk:%d state:%d",
                        (unsigned long long)cache->block, (unsigned long long)cache->cacheblock, 
			(unsigned long long)request_block,cache->disk,cache->state);
                dmc->replace++;
        } else {
                DPRINTK("Insert block: %llu at empty frame: %llu",
			(unsigned long long)request_block, (unsigned long long)cache->cacheblock);
        }
        cache_insert(dmc, request_block, cache , disk); /* Update metadata first */

        job = new_kcached_job(dmc, bio, request_block, cache);

        head = to_bytes(offset);
        left = (virtual_mapping[disk].src_dev->bdev->bd_inode->i_size>>9) - request_block;
        if (left < dmc->block_size) {
                tail = to_bytes(left) - bio->bi_size - head;
                job->src.count = left;
                job->dest.count = left;
        } else
                tail = to_bytes(dmc->block_size) - bio->bi_size - head;

        /* Requested block is aligned with a cache block */
        if (0 == head && 0 == tail)
                job->nr_pages= 0;
        else /* Need new pages to store extra data */
                job->nr_pages = dm_div_up(head, PAGE_SIZE) + dm_div_up(tail, PAGE_SIZE);
        job->rw = READ; /* Fetch data from the source device */

	DPRINTK("Queue job for %llu (need %u pages)",
			(unsigned long long)bio->bi_sector, job->nr_pages);

	queue_job(job);

        return 0;
}

/*
 * Handle a write cache miss:
 *  If write-through, forward the request to source device.
 *  If write-back, update the metadata; fetch the necessary block from source
 *  device; write to cache device.
 */
static int cache_write_miss (struct cache_c *dmc, struct bio* bio, int disk,
		struct cacheblock *allocate) {
        struct cacheblock *cache ;

        unsigned int offset, head, tail;
        struct kcached_job *job;
        sector_t request_block, left;

        if (dmc->write_policy == WRITE_THROUGH) { /* Forward request to source */
                bio->bi_bdev = virtual_mapping[disk].src_dev->bdev;
                return 1;
        }
	offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
	request_block = bio->bi_sector - offset;

	if( allocate == NULL){
		cache = request_cache_block(dmc,disk);

		if(is_state(cache->state, RESERVED) || is_state(cache->state, WRITEBACK )) {
			DPRINTK("Got a spot RESERVED cacheblock: %llu val:%d ",
					(unsigned long long)cache->cacheblock,cache->state);
			DPRINTK("Add to bio list %s(%llu)",
					dmc->cache_dev->name, (unsigned long long)bio->bi_sector);
			bio_list_add(&cache->bios, bio);
			return 0;
		}

		if (is_state(cache->state,VALID)) {
			DPRINTK("Replacing Block:%llu to:%llu disk: %d",
					(unsigned long long)cache->block, (unsigned long long)request_block,
					cache->disk);
			dmc->replace++;
		} else DPRINTK("Insert block %llu at empty frame %llu",
				(unsigned long long)request_block, (unsigned long long)cache->cacheblock);

		/* Write delay */
		cache_insert(dmc, request_block, cache,disk); /* Update metadata first */
	}else{
		DPRINTK("Write Allocate updated: %llu",request_block);
		cache = allocate;

        	spin_lock(&cache->lock);
	        set_state(cache->state, RESERVED);
	        spin_unlock(&cache->lock);
	}
        set_state(cache->state, DIRTY);
	dmc->dirty_blocks++;
	virtual_mapping[cache->disk].dirty_blocks++;
		
        job = new_kcached_job(dmc, bio, request_block, cache);
        if (dmc->write_policy == WRITE_ALLOCATE)
		job->allocate = 1;

        head = to_bytes(offset);
        left = (virtual_mapping[disk].src_dev->bdev->bd_inode->i_size>>9) - request_block;
        if (left < dmc->block_size) {
                tail = to_bytes(left) - bio->bi_size - head;
                job->src.count = left;
                job->dest.count = left;
        } else
                tail = to_bytes(dmc->block_size) - bio->bi_size - head;

        if (0 == head && 0 == tail) { /* Requested is aligned with a cache block */
                job->nr_pages = 0;
                job->rw = WRITE;
        } else if (head && tail){ /* Special case: need to pad both head and tail */
                job->nr_pages = dm_div_up(to_bytes(job->src.count), PAGE_SIZE);
                job->rw = READ;
        } else {
                if (head) { /* Fetch only head */
                        job->src.count = to_sector(head);
                        job->nr_pages = dm_div_up(head, PAGE_SIZE);
                } else { /* Fetch only tail */
                        job->src.sector = bio->bi_sector + to_sector(bio->bi_size);
                        job->src.count = to_sector(tail);
                        job->nr_pages = dm_div_up(tail, PAGE_SIZE);
                }
                job->rw = READ;
        }

        queue_job(job);

        return 0;
}


/* Handle cache misses */
static int cache_miss(struct cache_c *dmc, struct bio* bio, int disk) {
        dmc->misses++;
        virtual_mapping[disk].misses++;
        if (bio_data_dir(bio) == READ){
                dmc->read_misses++;
                virtual_mapping[disk].read_misses++;
                return cache_read_miss(dmc, bio, disk);
        }else{
                dmc->write_misses++;
                virtual_mapping[disk].write_misses++;
                return cache_write_miss(dmc, bio, disk, NULL);
        }
}

static int virtual_cache_map(struct bio *bio)
{
	int i = 0, ret = -1;

	for (i=0; i < ctn_dm_dev ; i++)
	{
		if(virtual_mapping[i].vcache_dev == bio->bi_bdev->bd_dev )
			ret = i;
	}
	if(ret == -1)
		DMERR("Virtual cache mapping not found %llu",
				(long long unsigned int)bio->bi_bdev->bd_dev);
	return ret;
}


/****************************************************************************
 *  Functions for implementing the operations on a cache mapping.
 ****************************************************************************/
/*
 * Decide the mapping and perform necessary cache operations for a bio request.
 */
static int cache_map(struct dm_target *ti, struct bio *bio,
                union map_info *map_context){
        struct cache_c *dmc = shared_cache;
        struct cacheblock *cache;
        struct duplicate_node * duplicate_node;
        struct reverse_node * reverse_node;
	struct source_tracker * pos;
	struct source_tracker * n;
	struct source_tracker * tmp;
        sector_t request_block, offset;
        int res=0, disk;

        offset = bio->bi_sector & dmc->block_mask;
        request_block = bio->bi_sector - offset;
        disk = virtual_cache_map(bio);

        /*DPRINTK("Got a %s for %llu disk: %d ((%llu:%llu), %u bytes)",
                        bio_rw(bio) == WRITE ? "WRITE" : (bio_rw(bio) == READ ?
                        "READ":"READA"),(unsigned long long) bio->bi_sector, disk,
			(unsigned long long)request_block, (unsigned long long)offset, 
                        (unsigned)bio->bi_size);*/

        if (bio_data_dir(bio) == READ){
                dmc->reads++;
                virtual_mapping[disk].reads++;
        }else{
                dmc->writes++;
                virtual_mapping[disk].writes++;
        }

        //begin

        if(DEDUP > 0  && bio->bi_size >= (dmc->block_size * sector_size))
        {
		printk("----------------------------------------------------------------\n");
		printk("Starting cache_map\n");
        	printk("looking for %llu, (request: %llu, disk: %llu)\n", get_block_index(request_block,disk), request_block, disk);
        	duplicate_node = find_duplicate(duplicate_tree, get_block_index(request_block,disk));

        	if(duplicate_node != NULL)
        	{
        		printk("Found a node with source = %llu, device = %llu and cache = %llu\n", duplicate_node->sourceblock, duplicate_node->device_id, duplicate_node->cacheblock);

        		if(bio_data_dir(bio) == READ)
        		{
        			printk("READ HIT\n");
				printk("----------------------------------------------------------------\n");
        			return cache_hit(dmc, bio, &dmc->blocks[duplicate_node->cacheblock]);
        		}
        		else
        		{
        			printk("WRITE\n");

        			reverse_node = find_reverse(reverse_tree, duplicate_node->cacheblock);

        			if(reverse_node != NULL)
        			{
        				printk("Found reverse_node with cache = %llu and count %d\n", reverse_node->cacheblock, reverse_node->count);

        				if(reverse_node->count > 1)
        				{
        					printk("Multiple Dependents\n");

        					if(dmc->write_policy == WRITE_THROUGH)
        					{
        						printk("WRITE_THROUGH\n");
        						remove_duplicate(duplicate_tree, get_block_index(request_block,disk));
        						reverse_node->count --;
							remove_source_tracker(reverse_node, get_block_index(request_block,disk));
							printk("WRITE MISS\n");
							printk("----------------------------------------------------------------\n");
        						return cache_miss(dmc, bio, disk);
        					}
        					else if(dmc->write_policy == WRITE_BACK)
        					{
        						printk("WRITE_BACK\n");
        						remove_duplicate(duplicate_tree, get_block_index(request_block,disk));
        						reverse_node->count --;

							remove_source_tracker(reverse_node, get_block_index(request_block,disk));

							if(reverse_node->dirty_count == 0)
							{
								set_state(dmc->blocks[reverse_node->cacheblock].state, VALID);
								dmc->dirty_blocks--;
								virtual_mapping[dmc->blocks[reverse_node->cacheblock].disk].dirty_blocks--;
							}

        						printk("WRITE MISS\n");
							printk("----------------------------------------------------------------\n");
        						return cache_miss(dmc, bio, disk);
        					}
        				}
        				else
        				{
        					printk("Single Dependent\n");

        					if(dmc->write_policy == WRITE_THROUGH)
        					{
        						printk("WRITE_THROUGH\n");
        						reverse_node->count --;
							remove_source_tracker(reverse_node, get_block_index(request_block,disk));

							if(reverse_node->fingerprint == NULL)
							{
								printk("reverse has a null fingerprint\n");
							}

        						//remove_fingerprint(fingerprint_tree, reverse_node->fingerprint);
							remove_fingerprint(fingerprint_table, reverse_node->fingerprint, dmc->size);
							remove_reverse(reverse_tree, duplicate_node->cacheblock);
							cache_invalidate(dmc, &dmc->blocks[duplicate_node->cacheblock]);
							remove_duplicate(duplicate_tree, get_block_index(request_block,disk));
        						printk("WRITE MISS\n");
							printk("----------------------------------------------------------------\n");
							return cache_miss(dmc, bio, disk);
        					}
        					else if(dmc->write_policy == WRITE_BACK)
        					{
        						printk("WRITE_BACK\n");
        						remove_duplicate(duplicate_tree, get_block_index(request_block,disk));
        						reverse_node->count --;

							remove_source_tracker(reverse_node, get_block_index(request_block,disk));

							if(reverse_node->dirty_count == 0)
							{
								set_state(dmc->blocks[reverse_node->cacheblock].state, VALID);
								dmc->dirty_blocks--;
								virtual_mapping[dmc->blocks[reverse_node->cacheblock].disk].dirty_blocks--;
							}

        						remove_reverse(reverse_tree, duplicate_node->cacheblock);
        						//remove_fingerprint(fingerprint_tree, reverse_node->fingerprint);
							remove_fingerprint(fingerprint_table, reverse_node->fingerprint, dmc->size);
        						cache_invalidate(dmc, &dmc->blocks[duplicate_node->cacheblock]);
        						printk("WRITE MISS\n");
							printk("----------------------------------------------------------------\n");
							//return cache_hit(dmc, bio, &dmc->blocks[duplicate_node->cacheblock]);
        						return cache_miss(dmc, bio, disk);
        					}
        				}
        			}
        		}
        	} 
        }

        //done

	// push to WSS analysis
#if WSS_ANALYSIS 
	push_wss(bio->bi_sector, disk);
#endif
        if(is_state(virtual_mapping[disk].state,ENABLED)){
                cache = radix_tree_lookup(dmc->cache, get_block_index(request_block,disk));
  /*              DPRINTK("Lookup for %llu (v_disk:%d index:%llu)",
			(unsigned long long)request_block,disk,
			(unsigned long long)get_block_index(request_block,disk));

                if(cache != NULL){
                        if (is_state(cache->state, VALID) || is_state(cache->state, RESERVED)) {
                                if (cache->block == request_block && cache->disk == disk)
                                        res = 1;
                        }else{
                                res = -1;
                                DPRINTK("cache(%llu:%llu) state %d-%s\n",
					(unsigned long long)cache->block,
					(unsigned long long)cache->cacheblock,cache->state,
                                        (cache->state == 0 ? "INVALID":
                                        (cache->state == 1 ? "VALID":
                                        (cache->state == 2 ? "RESERVED":
                                        (cache->state == 4 ? "DIRTY":
                                        (cache->state == 8 ? "WRITEBACK":
                                        (cache->state == 16 ? "WRITETHROUGH":"")))))));
                        }
                }
                if (-1 == res){
                        DPRINTK("Cache lookup: Block Invalid %llu", (unsigned long long)request_block);
		//	printk("Dulcardo we are missing bios!! watch out!!\n");
                }else
                        DPRINTK("Cache lookup: Block %llu:%llu(%s)",
				(unsigned long long)request_block,
				res == 1 ? (unsigned long long)cache->cacheblock:
						(unsigned long long)res,
	                                        1 == res ? "HIT" : "MISS");
*/
                if (cache != NULL ){  // Cache hit; server request from cache 
                        return  cache_hit(dmc, bio, cache);
                }else if (0 == res){ // Cache miss; replacement block is found 
                        return cache_miss(dmc, bio, disk);
                }
        }
        // Forward to source device 
        bio->bi_bdev = virtual_mapping[disk].src_dev->bdev;

        return 1;
}


struct meta_dmc {
	sector_t size;
	unsigned int block_size;
	unsigned int assoc;
	unsigned int write_policy;
	unsigned int chksum;
};

/* Load metadata stored by previous session from disk. */
/*
static int load_metadata(struct cache_c *dmc) {
	struct dm_io_region where;
	unsigned long bits;
	sector_t dev_size = dmc->cache_dev->bdev->bd_inode->i_size >> 9;
	sector_t meta_size, *meta_data, i, j, index = 0, limit, order;
	struct meta_dmc *meta_dmc;
	unsigned int chksum = 0, chksum_sav, consecutive_blocks;

	meta_dmc = (struct meta_dmc *)vmalloc(512);
	if (!meta_dmc) {
		DMERR("load_metadata: Unable to allocate memory");
		return 1;
	}

	where.bdev = dmc->cache_dev->bdev;
	where.sector = dev_size - 1;
	where.count = 1;
	dm_io_sync_vm(1, &where, READ, meta_dmc, &bits, dmc);
	DPRINTK("Loaded cache conf: block size(%u), cache size(%llu), " \
	        "associativity(%u), write policy(%u), chksum(%u)",
	        meta_dmc->block_size, meta_dmc->size,
	        meta_dmc->assoc, meta_dmc->write_policy,
	        meta_dmc->chksum);

	dmc->block_size = meta_dmc->block_size;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;

	dmc->size = meta_dmc->size;
	dmc->bits = ffs(dmc->size) - 1;

	dmc->assoc = meta_dmc->assoc;
	consecutive_blocks = dmc->assoc < CONSECUTIVE_BLOCKS ?
	                     dmc->assoc : CONSECUTIVE_BLOCKS;
	dmc->consecutive_shift = ffs(consecutive_blocks) - 1;

	dmc->write_policy = meta_dmc->write_policy;
	chksum_sav = meta_dmc->chksum;

	vfree((void *)meta_dmc);


	order = dmc->size * sizeof(struct cacheblock);
	DMINFO("Allocate %lluKB (%luB per) mem for %llu-entry cache" \
	       "(capacity:%lluMB, associativity:%u, block size:%u " \
	       "sectors(%uKB), %s)",
	       (unsigned long long) order >> 10, (unsigned long) sizeof(struct cacheblock),
	       (unsigned long long) dmc->size,
	       (unsigned long long) dmc->size * dmc->block_size >> (20-SECTOR_SHIFT),
	       dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT),
	       dmc->write_policy ? "write-back" : "write-through");
	dmc->cache = (struct cacheblock *)vmalloc(order);
	if (!dmc->cache) {
		DMERR("load_metadata: Unable to allocate memory");
		return 1;
	}

	meta_size = dm_div_up(dmc->size * sizeof(sector_t), 512);
	// When requesting a new bio, the number of requested bvecs has to be
	//   less than BIO_MAX_PAGES. Otherwise, null is returned. In dm-io.c,
	//   this return value is not checked and kernel Oops may happen. We set
	//   the limit here to avoid such situations. (2 additional bvecs are
	//   required by dm-io for bookeeping.)
	 
	limit = (BIO_MAX_PAGES - 2) * (PAGE_SIZE >> SECTOR_SHIFT);
	meta_data = (sector_t *)vmalloc(to_bytes(min(meta_size, limit)));
	if (!meta_data) {
		DMERR("load_metadata: Unable to allocate memory");
		vfree((void *)dmc->cache);
		return 1;
	}

	while(index < meta_size) {
		where.sector = dev_size - 1 - meta_size + index;
		where.count = min(meta_size - index, limit);
		dm_io_sync_vm(1, &where, READ, meta_data, &bits, dmc);

		for (i=to_bytes(index)/sizeof(sector_t), j=0;
		     j<to_bytes(where.count)/sizeof(sector_t) && i<dmc->size;
		     i++, j++) {
			if(meta_data[j]) {
				dmc->cache[i].block = meta_data[j];
				dmc->cache[i].state = 1;
			} else
				dmc->cache[i].state = 0;
		}
		chksum = csum_partial((char *)meta_data, to_bytes(where.count), chksum);
		index += where.count;
	}

	vfree((void *)meta_data);

	if (chksum != chksum_sav) { // Check the checksum of the metadata 
		DPRINTK("Cache metadata loaded from disk is corrupted");
		vfree((void *)dmc->cache);
		return 1;
	}

	DMINFO("Cache metadata loaded from disk (offset %llu)",
	       (unsigned long long) dev_size - 1 - (unsigned long long) meta_size);;

	return 0;
}

// Store metadata onto disk. 
static int dump_metadata(struct cache_c *dmc) {
	struct dm_io_region where;
	unsigned long bits;
	sector_t dev_size = dmc->cache_dev->bdev->bd_inode->i_size >> 9;
	sector_t meta_size, i, j, index = 0, limit, *meta_data;
	struct meta_dmc *meta_dmc;
	unsigned int chksum = 0;

	meta_size = dm_div_up(dmc->size * sizeof(sector_t), 512);
	limit = (BIO_MAX_PAGES - 2) * (PAGE_SIZE >> SECTOR_SHIFT);
	meta_data = (sector_t *)vmalloc(to_bytes(min(meta_size, limit)));
	if (!meta_data) {
		DMERR("dump_metadata: Unable to allocate memory");
		return 1;
	}

	where.bdev = dmc->cache_dev->bdev;
	while(index < meta_size) {
		where.sector = dev_size - 1 - meta_size + index;
		where.count = min(meta_size - index, limit);

		for (i=to_bytes(index)/sizeof(sector_t), j=0;
		     j<to_bytes(where.count)/sizeof(sector_t) && i<dmc->size;
		     i++, j++) {
			// Assume all invalid cache blocks store 0. We lose the block that
			// is actually mapped to offset 0.
			meta_data[j] = dmc->cache[i].state ? dmc->cache[i].block : 0;
		}
		chksum = csum_partial((char *)meta_data, to_bytes(where.count), chksum);

		dm_io_sync_vm(1, &where, WRITE, meta_data, &bits, dmc);
		index += where.count;
	}

	vfree((void *)meta_data);

	meta_dmc = (struct meta_dmc *)vmalloc(512);
	if (!meta_dmc) {
		DMERR("dump_metadata: Unable to allocate memory");
		return 1;
	}

	meta_dmc->block_size = dmc->block_size;
	meta_dmc->size = dmc->size;
	meta_dmc->assoc = dmc->assoc;
	meta_dmc->write_policy = dmc->write_policy;
	meta_dmc->chksum = chksum;

	DPRINTK("Store metadata to disk: block size(%u), cache size(%llu), " \
	        "associativity(%u), write policy(%u), checksum(%u)",
	        meta_dmc->block_size, (unsigned long long) meta_dmc->size,
	        meta_dmc->assoc, meta_dmc->write_policy,
	        meta_dmc->chksum);

	where.sector = dev_size - 1;
	where.count = 1;
	dm_io_sync_vm(1, &where, WRITE, meta_dmc, &bits, dmc);

	vfree((void *)meta_dmc);

	DMINFO("Cache metadata saved to disk (offset %llu)",
	       (unsigned long long) dev_size - 1 - (unsigned long long) meta_size);

	return 0;
}*/

static void put_src_devices(void)
{
/* TODO
 * Implement cleaning in case of error 
 * and putting all src_dev is required
 */
	DPRINTK(" Sources devices to put: %d",cnt_active_map);
	return;
}

static int populate_vm_mapping(int idx_mapping, int dev_size )
{
	virtual_mapping[idx_mapping].identifier = idx_mapping;
	virtual_mapping[idx_mapping].dev_size = dev_size;

	if(idx_mapping <= 0)
		virtual_mapping[idx_mapping].dev_offset = 0;
	else	
		virtual_mapping[idx_mapping].dev_offset = virtual_mapping[idx_mapping-1].dev_offset + 
			virtual_mapping[idx_mapping-1].dev_size;

        virtual_mapping[idx_mapping].reads = 0;
        virtual_mapping[idx_mapping].dirty_blocks = 0;
        virtual_mapping[idx_mapping].writes = 0;
        virtual_mapping[idx_mapping].cache_hits = 0;
        virtual_mapping[idx_mapping].read_hits = 0;
        virtual_mapping[idx_mapping].invalidates = 0;
        virtual_mapping[idx_mapping].inserts = 0;
        virtual_mapping[idx_mapping].allocate = 0;
        virtual_mapping[idx_mapping].wss = 0;
        virtual_mapping[idx_mapping].misses = 0;
        virtual_mapping[idx_mapping].read_misses = 0;
        virtual_mapping[idx_mapping].write_misses = 0;

	return 0;
}

static int get_vm_index(char *vm_identifier){
	int i;
	printk("VM_id %s\n",vm_identifier);

	for (i=0; i < ctn_dm_dev ; i ++)
	{
		if (strcmp(virtual_mapping[i].vm_id , vm_identifier) == 0) {
			if(is_state(virtual_mapping[i].state,ENABLED)){
				return -1;
			}else if(is_state(virtual_mapping[i].state,DISABLED)){
				cnt_active_map++;
				return i;
			}
		}
	}
	set_state(virtual_mapping[ctn_dm_dev].state,EMPTY);
	ctn_dm_dev++;
	cnt_active_map++;
	
	return (ctn_dm_dev-1);
}

/*
 * Construct a cache mapping.
 *  arg[0]: path to source device
 *  arg[1]: path to cache device
 *  arg[2]: cache persistence (if set, cache conf is loaded from disk)
 * Cache configuration parameters (if not set, default values are used.
 *  arg[3]: cache block size (in sectors)
 *  arg[4]: cache size (in blocks)
 *  arg[5]: cache associativity
 *  arg[6]: write caching policy
 *  arg[7]: virtual machine ID
 */
static int cache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct cache_c *dmc;
	unsigned int consecutive_blocks, persistence = 0;
	sector_t localsize, i, order;
	sector_t data_size, meta_size, dev_size;
	unsigned long long cache_size;
	int r = -EINVAL;
	struct mapped_device *mapped_dev;
	struct dm_dev *virtual_cache;
	struct dm_dev_internal *dd = NULL;
	int idx_mapping = -1;
        struct sysinfo sys_info;
	int limit;

	if (argc < 2) {
		ti->error = "dm-cache: Need at least 2 arguments (src dev and cache dev)";
		goto bad;
	}

	/* This is the first time a mapping is created */
	if(init_flag == 0){
		virtual_mapping = kmalloc(sizeof(*virtual_mapping)*MAX_SRC_DEVICES , GFP_KERNEL);
		if (virtual_mapping == NULL){
			ti->error = "dm-cache: Failed to allocate cache context";
			r = ENOMEM;
			goto bad;
		}
		shared_cache = kmalloc(sizeof(*shared_cache), GFP_KERNEL);
	}

	dmc = shared_cache;
	if (dmc == NULL) {
		ti->error = "dm-cache: Failed to allocate cache context";
		r = ENOMEM;
		goto bad1;
	}
	
	/* Get the index for this VM */
	if(argc >= 8) {
		idx_mapping = get_vm_index(argv[7]);
		printk("&idx_mapping: %d\n",idx_mapping);
		if(idx_mapping >= 0){
			strcpy(virtual_mapping[idx_mapping].vm_id,argv[7]);

			// Allocating the share
			if (sscanf(argv[8], "%d", &limit) != 1){
				ti->error = "dm-cache: Invalid cache persistence";
				r = -EINVAL;
				goto bad1;	
			}
			printk("find3\n");
			// Initialize the Wss structure
#if WSS_ANALYSIS 
			r = wss_init(idx_mapping);
			if (r){
				ti->error = "wss-struct: Error initializing the WSS struct";
				r = -EINVAL;
				goto bad1;	
			}
#endif

		}else{
			ti->error = "dm-cache: Virtual Machine identifier already exits";
			r = -EINVAL;
			goto bad2;
		}	

	}else{
		ti->error = "dm-cache: Requires Virtual Machine identifier";
		r = -EINVAL;
		goto bad2;
	}

	/*  Adding source device */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,8)
	r = dm_get_device(ti, argv[0],
			dm_table_get_mode(ti->table), &virtual_mapping[idx_mapping].src_dev);
#else
        r = dm_get_device(ti, argv[0],0,0,
                        dm_table_get_mode(ti->table), &virtual_mapping[idx_mapping].src_dev);
#endif

	virtual_mapping[idx_mapping].ti = ti;

	if (r) {
		ti->error = "dm-cache: Source device lookup failed";
		goto bad1;
	} 
	DPRINTK("Registering device %s:%llu",virtual_mapping[idx_mapping].src_dev->name,
			(long long unsigned int)virtual_mapping[idx_mapping].src_dev->bdev->bd_dev);

	/* Adding virtual cache devices */
	mapped_dev = dm_table_get_md(ti->table);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,8)
	r = dm_get_device(ti, dm_device_name(mapped_dev),
			dm_table_get_mode(ti->table), &virtual_cache);
#else
	r = dm_get_device(ti, dm_device_name(mapped_dev),0,0,
			dm_table_get_mode(ti->table), &virtual_cache);
#endif
	if (r) {
		ti->error = "dm-cache: virtual cache device lookup failed";
		goto bad1;
	}else {
		virtual_mapping[idx_mapping].vcache_dev = virtual_cache->bdev->bd_dev;

		DPRINTK("Registering %d device %s:%llu",
				idx_mapping,
				dm_device_name(mapped_dev),
				(long long unsigned int)virtual_mapping[idx_mapping].vcache_dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,8)
		dm_put_device(ti, virtual_cache);
#else
		dm_put(mapped_dev);
		dm_put_device(ti, virtual_cache);
#endif
	}

	printk("doom3\n");	

	/* Populate virtual machine mapping configuration */
	if(is_state(virtual_mapping[idx_mapping].state, EMPTY))
		populate_vm_mapping(idx_mapping,ti->len);
	put_state(virtual_mapping[idx_mapping].state, ENABLED);

	/* Adding global cache device */
	if(init_flag == 0) {
		DPRINTK("Registering %s",argv[1]);
		dd =  kmalloc(sizeof(*dd), GFP_KERNEL);
		dd->dm_dev.mode = dm_table_get_mode(ti->table);		
		dd->dm_dev.bdev = lookup_bdev(argv[1]);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,8)
		r = blkdev_get( dd->dm_dev.bdev , dd->dm_dev.mode,NULL);
#else
		r = blkdev_get( dd->dm_dev.bdev , dd->dm_dev.mode);
#endif
		printk("doom5\n");

		if (r) {
			ti->error = "dm-cache: Cache device lookup failed";
			kfree(dd);
			goto bad2;
		}else{

			format_dev_t(dd->dm_dev.name, dd->dm_dev.bdev->bd_dev);
			atomic_set(&dd->count, 0);
			atomic_inc(&dd->count);

			dmc->cache_dev = &dd->dm_dev;

			DPRINTK("Registering device %s:%llu",argv[1],
					(long long unsigned int)dmc->cache_dev->bdev->bd_dev);
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,8)
		dmc->io_client = dm_io_client_create();
#else
		dmc->io_client = dm_io_client_create(DMCACHE_COPY_PAGES);
#endif
		if (IS_ERR(dmc->io_client)) {
			r = PTR_ERR(dmc->io_client);
			ti->error = "Failed to create io client\n";
			goto bad3;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,8)
		dmc->kcp_client = dm_kcopyd_client_create();
		if (dmc->kcp_client == NULL) {
			ti->error = "Failed to initialize kcopyd client\n";
			goto bad4;
		}

#else
		r = dm_kcopyd_client_create(DMCACHE_COPY_PAGES, &dmc->kcp_client);
		if (r) {
			ti->error = "Failed to initialize kcopyd client\n";
			goto bad4;
		}
#endif

		r = kcached_init(dmc);
		if (r) {
			ti->error = "Failed to initialize kcached";
			goto bad5;
		}
		
		//create the bio set
		dmcache_bio_set = bioset_create(DMCACHE_MIN_IOS, 0);
		if(dmcache_bio_set == NULL){
			ti->error = "Failed to create bio_set";
			goto bad5;
		}
	}

	if (argc >= 3) {
		if (sscanf(argv[2], "%u", &persistence) != 1) {
			ti->error = "dm-cache: Invalid cache persistence";
			r = -EINVAL;
			goto bad6;
		}
	}

	if(init_flag != 0) {
		// calculating share partitioning
		DPRINTK("share %s(%d)",virtual_mapping[idx_mapping].vm_id,limit);
		virtual_mapping[idx_mapping].limit =  ((dmc->size * limit ) / 100);

		DMINFO("Add new entry :%d  (%luB per) mem for %llu-entry cache" \
				"associativity:%u, block size:%u " \
				"sectors(%uKB), %s) limit (%lu)",idx_mapping,
				(unsigned long) sizeof(struct cacheblock),
				(unsigned long long) dmc->size,
				dmc->assoc, dmc->block_size,
				dmc->block_size >> (10-SECTOR_SHIFT),
				dmc->write_policy == 1 ? "write-back" : 
				(dmc->write_policy == 0 ? "write-through": "write-allocate"),
				(unsigned long) virtual_mapping[idx_mapping].limit);

		goto init_sc;
	}

	if (argc >= 4) {
		if (sscanf(argv[3], "%u", &dmc->block_size) != 1) {
			ti->error = "dm-cache: Invalid block size";
			r = -EINVAL;
			goto bad6;
		}
		if (!dmc->block_size || (dmc->block_size & (dmc->block_size - 1))) {
			ti->error = "dm-cache: Invalid block size";
			r = -EINVAL;
			goto bad6;
		}
	} else
		dmc->block_size = DEFAULT_BLOCK_SIZE;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;

	if (argc >= 5) {
		if (sscanf(argv[4], "%llu", &cache_size) != 1) {
			ti->error = "dm-cache: Invalid cache size";
			r = -EINVAL;
			goto bad6;
		}
		dmc->size = (sector_t) cache_size;
	} else
		dmc->size = DEFAULT_CACHE_SIZE;
	localsize = dmc->size;
	dmc->bits = ffs(dmc->size) - 1;

	if (argc >= 6) {
		if (sscanf(argv[5], "%u", &dmc->assoc) != 1) {
			ti->error = "dm-cache: Invalid cache associativity";
			r = -EINVAL;
			goto bad6;
		}
		if (!dmc->assoc || (dmc->assoc & (dmc->assoc - 1)) ||
			dmc->size < dmc->assoc) {
			ti->error = "dm-cache: Invalid cache associativity";
			r = -EINVAL;
			goto bad6;
		}
	} else
		dmc->assoc = DEFAULT_CACHE_ASSOC;

	DMINFO("%lld", dmc->cache_dev->bdev->bd_inode->i_size);
	dev_size = dmc->cache_dev->bdev->bd_inode->i_size >> 9;
	data_size = dmc->size * dmc->block_size;

	if ((data_size ) > dev_size) {
		DMERR("Requested cache size exeeds the cache device's capacity" \
		      "(%llu > %llu)",
  		      (unsigned long long) data_size,
  		      (unsigned long long) dev_size);
		ti->error = "dm-cache: Invalid cache size";
		r = -EINVAL;
		goto bad6;
	}
	consecutive_blocks = dmc->assoc < CONSECUTIVE_BLOCKS ?
	                     dmc->assoc : CONSECUTIVE_BLOCKS;
	dmc->consecutive_shift = ffs(consecutive_blocks) - 1;

	if (argc >= 7) {
		if (sscanf(argv[6], "%u", &dmc->write_policy) != 1) {
			ti->error = "dm-cache: Invalid cache write policy";
			r = -EINVAL;
			goto bad6;
		}
		if (dmc->write_policy != 0 && dmc->write_policy != 1 && dmc->write_policy != 2) {
			ti->error = "dm-cache: Invalid cache write policy";
			r = -EINVAL;
			goto bad6;
		}
	} else
		dmc->write_policy = DEFAULT_WRITE_POLICY;

        order = dmc->size * sizeof(struct cacheblock) +
                sizeof(*dmc->lru);

        // Check system information
        si_meminfo (&sys_info);
        printk("Free memory before: %lu needed:%llu\n",sys_info.freeram,
		(unsigned long long) (order>0 ? (order>>10)/4 : 0));

        if(sys_info.freeram < (order>>10)/4){
                DMERR("Requested cache size needs (%llukB) free Memory, Free memory (%lukB)",
                                (unsigned long long) order>>10,
                                sys_info.freeram * 4);

                ti->error =  "No enough Memory to allocate dm-cache metadatai";
                r = -ENOMEM;
                goto bad6;
        }

         /* Allocating all the space for Metadata  */
        dmc->cache = (struct radix_tree_root *) vmalloc(sizeof(*dmc->cache));
        if (!dmc->cache) {
                ti->error = "Unable to allocate memory";
                r = -ENOMEM;
                goto bad6;
        }
        INIT_RADIX_TREE(dmc->cache, GFP_NOIO);

        dmc->lru = (struct list_head *)vmalloc(sizeof(*dmc->lru));
        if(dmc->lru == NULL){
                ti->error = "Unable to allocate memory for LRU list";
                r = -ENOMEM;
                goto bad7;
        }

        INIT_LIST_HEAD(dmc->lru);

        dmc->blocks = (struct cacheblock *) vmalloc(dmc->size * (sizeof(struct cacheblock)));
        if(dmc->blocks == NULL) {
                ti->error = "Unable to allocate memory for dmc cache blocks";
                r = -ENOMEM;
                goto bad8;
        }

	// calculating share partitioning
	virtual_mapping[idx_mapping].limit =  (dmc->size * limit ) / 100;


	DMINFO("Allocate %lluKB (%luB per) mem for %llu-entry cache" \
	       "(capacity:%lluMB, associativity:%u, block size:%u " \
	       "sectors(%uKB), %s)",
	       (unsigned long long) order >> 10, (unsigned long) sizeof(struct cacheblock),
	       (unsigned long long) dmc->size,
	       (unsigned long long) data_size >> (20-SECTOR_SHIFT),
	       dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT),
	       dmc->write_policy == 1 ? "write-back" : 
	       (dmc->write_policy == 0 ? "write-through":"write-allocate"));

        for (i=0; i < dmc->size; i++) {
                bio_list_init(&dmc->blocks[i].bios);
                dmc->blocks[i].state = 0;
                spin_lock_init(&dmc->blocks[i].lock);
                dmc->blocks[i].cacheblock = i;
                dmc->blocks[i].disk = -1;
                list_add(&dmc->blocks[i].list, dmc->lru);
        }

	dmc->allocate = 0;
        dmc->counter = 0;
        dmc->dirty_blocks = 0;
        dmc->reads = 0;
        dmc->writes = 0;
        dmc->cache_hits = 0;
        dmc->replace = 0;
        dmc->writeback = 0;
        dmc->dirty = 0;

        dmc->misses = 0;
        dmc->read_misses = 0;
        dmc->write_misses = 0;
        dmc->read_hits = 0;
        dmc->invalidates = 0;
        dmc->inserts = 0;

	dmc->potential = 0;
	dmc->actual = 0;

	if(DEDUP > 0)
	{
		//fingerprint_tree = get_tree_root();
		fingerprint_table = create_fingerprint_table(dmc->size);
		duplicate_tree = get_radix_root();
		reverse_tree = get_radix_root();
	}

init_sc:
	ti->split_io = dmc->block_size;
	//ti->max_io_len = dmc->block_size;
	ti->private = &virtual_mapping[idx_mapping];

	init_flag = 1;
	return 0;

bad8:
        vfree(dmc->lru);
bad7:
        vfree(dmc->cache);
bad6:
	kcached_client_destroy(dmc);
bad5:
	dm_kcopyd_client_destroy(dmc->kcp_client);
bad4:
	dm_io_client_destroy(dmc->io_client);
	blkdev_put(dd->dm_dev.bdev , dd->dm_dev.mode);
	kfree(dd);
bad3:
//	dm_put_device(ti, dmc->cache_dev);
	dm_put_device(ti,virtual_mapping[idx_mapping].src_dev);

bad2:
	put_src_devices();
	kfree(shared_cache);
bad1:
	kfree(virtual_mapping);
bad:
	return r;
}

static void  cache_flush(struct cache_c *dmc, int disk)
{
	struct cacheblock *pos;
	struct cacheblock *cache;
	struct list_head *temp;
	struct source_tracker * post;
	struct source_tracker * n;
	struct source_tracker * tmp;
	struct reverse_node * reverse_node;
	struct duplicate_node * duplicate_node;
//	unsigned int j;
	DMINFO("Flush dirty blocks (%llu) ...", (unsigned long long) dmc->dirty_blocks);

	down(&dmc->lru_mutex);
	list_for_each(temp, dmc->lru) {
		cache = list_entry(temp, struct cacheblock, list);
		if((cache->disk == disk || disk == -1) && is_state(cache->state, DIRTY)) {
			/*			j =1;
						for (pos = list_entry((temp)->next, struct cacheblock, list );
						&pos->list != (dmc->lru) && is_state(pos->state, DIRTY) &&
						pos->block == (cache->block + (j * dmc->block_size)) &&
						pos->disk == cache->disk;
						pos = list_entry(pos->list.next, struct cacheblock, list)) {
						j++;
						}
						dmc->dirty +=j;
			 */

			if(DEDUP > 0)
			{
				reverse_node = find_reverse(reverse_tree, cache->cacheblock);		
				
				if(reverse_node != NULL)
				{
					post = NULL;
					n = NULL;
					tmp = NULL;

					list_for_each_entry_safe(post, n, &reverse_node->first, list)
					{
						tmp = list_entry(&post->list, struct source_tracker, list);

						if(tmp->dirty == TRUE)
						{
							duplicate_node = find_duplicate(duplicate_tree, tmp->block_index);
							write_back_mod(dmc,cache,1, duplicate_node->sourceblock, duplicate_node->device_id);
							tmp->dirty = FALSE;
						}
					}

					//Testing
					//write_back(dmc, cache, 1);
				}
				else
				{
					write_back(dmc,cache,1);
				}
			}
			else
			{
				write_back(dmc,cache,1);
			}
		
//			temp = &pos->list;
		}
	}
	up(&dmc->lru_mutex);
}

static int flush_virtual_cache ( int disk )
{
        struct cacheblock *cache;
        struct list_head *temp;
        struct cache_c *dmc = shared_cache;
	struct reverse_node * reverse_node;
	struct duplicate_node * duplicate_node;
	struct source_tracker * source_tracker;

        DMINFO("Flushing virtual cache: %d",disk);

	down(&dmc->lru_mutex);
        list_for_each(temp, dmc->lru) {
                cache = list_entry(temp, struct cacheblock, list);

                if(cache->disk == disk && is_state(cache->state, VALID)) {

			
			if(DEDUP > 0)
			{
				printk("Dedup is 0\n");
				reverse_node = find_reverse(reverse_tree, cache->cacheblock);
		
				if(reverse_node != NULL)
				{
					printk("Reverse node exists\n");
					remove_device(duplicate_tree, reverse_node, cache->disk);

					if(reverse_node->count == 0)
					{
						printk("Reverse node count is 0\n");
						//remove_fingerprint(fingerprint_tree, reverse_node->fingerprint);
						remove_fingerprint(fingerprint_table, reverse_node->fingerprint, dmc->size);
						remove_reverse(reverse_tree, cache->cacheblock);
						cache_invalidate(dmc, cache);
					}
					else
					{
						printk("Reverse node count is %d\n", reverse_node->count);
						source_tracker = first_source_tracker(reverse_node);

						if(source_tracker == NULL)
						{
							printk("No source tracker??\n");
							cache_invalidate(dmc, cache);
						}
						else
						{	
							printk("Has a source tracker\n");					
							duplicate_node = find_duplicate(duplicate_tree, source_tracker->block_index);
							cache->disk = duplicate_node->device_id;
						}
					}
				}
				else
				{
					cache_invalidate(dmc, cache);
				}
			}
			else
			{
                        	cache_invalidate(dmc, cache);
			}
                }
        }
	up(&dmc->lru_mutex);
        return 0;
}

/*
 * Destroy the cache mapping.
 */
static void cache_dtr(struct dm_target *ti)
{
	struct cache_c *dmc = shared_cache;
	struct v_map *map_dev = (struct v_map *) ti->private;
	struct dm_dev_internal *dd;
	dd = container_of(dmc->cache_dev, struct dm_dev_internal,dm_dev);

	if (map_dev->dirty_blocks > 0) cache_flush(dmc,map_dev->identifier);

#if WSS_ANALYSIS 
	wss_dtr(map_dev->identifier);
#endif
	if(cnt_active_map == 1){
		kcached_client_destroy(dmc);

		bioset_free(dmcache_bio_set);
		dm_kcopyd_client_destroy(dmc->kcp_client);

		if (dmc->reads + dmc->writes > 0)
			DMINFO("stats: reads(%lu), writes(%lu), cache hits(%lu, 0.%lu)," \
					"replacement(%lu), replaced dirty blocks(%lu), " \
					"flushed dirty blocks(%lu), potential stores(%lu), actual stores(%lu)",
					dmc->reads, dmc->writes, dmc->cache_hits,
					dmc->cache_hits * 100 / (dmc->reads + dmc->writes),
					dmc->replace, dmc->writeback, dmc->dirty, dmc->potential, dmc->actual);

                vfree((void *)dmc->blocks);
                vfree((void *)dmc->lru);
		vfree((void *)dmc->cache);

		if(DEDUP > 0)
		{
			printk("Freeing structs\n");
			vfree((void *) reverse_tree);
			vfree((void *) duplicate_tree);
		}

		dm_io_client_destroy(dmc->io_client);

		put_state(map_dev->state,DISABLED);
		blkdev_put(dd->dm_dev.bdev , dd->dm_dev.mode);
		dm_put_device(map_dev->ti,map_dev->src_dev);

		kfree(dd);
		kfree(shared_cache);
		kfree(virtual_mapping);

		init_flag = 0;
		cnt_active_map--;
		
                DPRINTK("Free to destroy: %d",cnt_active_map);
		return;
	}

        flush_virtual_cache(map_dev->identifier);
	put_state(map_dev->state,DISABLED);
	/*
	 * Wait for jobs to complete before put the device
	 */
	wait_event(dmc->destroyq, !atomic_read(&dmc->nr_jobs));
	wait_event(dmc->wait_writeback, (map_dev->dirty_blocks ==  0));
	DPRINTK("Free to destroy: %d , %llu",cnt_active_map,map_dev->dirty_blocks);
	dm_put_device(map_dev->ti,map_dev->src_dev);
	cnt_active_map--;
	return;
}

/*
 * Report cache status:
 *  Output cache stats upon request of device status;
 *  Output cache configuration upon request of table status.
 */
static int cache_status(struct dm_target *ti, status_type_t type,
		char *result, unsigned int maxlen)
{
	struct cache_c *dmc = shared_cache;
	struct v_map *map_dev = (struct v_map *) ti->private;
	int sz = 0;

	int this_cpu;
	unsigned long long t, nanosec_rem;
	this_cpu = smp_processor_id();

	switch (type) {
		case STATUSTYPE_INFO:
			DMEMIT("VM-id\tstate\treads\twrites\tcache hits\tcache miss\t " \
					"read_miss\twrite_miss\tread_hit\t " \ 
					"inserts\tinvalidates\tlimit\tallocate\n");
			t = cpu_clock(this_cpu);
			//plot_data(map_dev->identifier);
			nanosec_rem = do_div(t, 1000000000);
			DMEMIT("%s\t%5llu\t%s\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu",
					map_dev->vm_id,t, map_dev->state == ENABLED ? "ENABLED" : "DISABLED",
					map_dev->reads, map_dev->writes, map_dev->cache_hits,
					map_dev->misses, map_dev->read_misses, map_dev->write_misses,
					map_dev->read_hits, map_dev->inserts, 
					map_dev->invalidates, map_dev->limit, map_dev->allocate,map_dev->wss);
			break;
		case STATUSTYPE_TABLE:
			DMEMIT("conf: capacity(%lluM), associativity(%u), block size(%uK), %s",
					(unsigned long long) dmc->size * dmc->block_size >> 11,
					dmc->assoc, dmc->block_size>>(10-SECTOR_SHIFT),
					dmc->write_policy == 1 ? "write-back":
					(dmc->write_policy == 0 ?"write-through":"write-allocate"));
			break;
	}
	return 0;
}
int set_vm_wss(int disk, int wss){
	DPRINTK("share %s(%d)",virtual_mapping[disk].vm_id,wss);
	virtual_mapping[disk].wss = wss;
	return 0;
}

int set_vm_limit(int disk, int limit){
	if(limit > 0){
		DPRINTK("share %s(%d)",virtual_mapping[disk].vm_id,limit);
		virtual_mapping[disk].limit =  ((shared_cache->size * limit ) / 100);
	}
	return 0;
}
int get_vm_limit(int disk){
	int ret = 0;
	if( shared_cache->size > 0)
		ret = (virtual_mapping[disk].limit * 100 )/ shared_cache->size;
	return ret;
}

int set_blk_limit(int disk, sector_t limit){
	if(limit > 0){
		DPRINTK("share %s(%d)",virtual_mapping[disk].vm_id,limit);
		virtual_mapping[disk].limit =  limit ;
	}
	return 0;
}
sector_t get_blk_limit(int disk){
	return virtual_mapping[disk].limit;
}
sector_t get_blk_global_limit(void){
	return shared_cache->size;
}

static int cache_message(struct dm_target *ti, unsigned int argc, char **argv)
{
        struct v_map *map_dev = (struct v_map *) ti->private;
        struct cache_c *dmc = shared_cache;
	int limit;

        if (argc != 1 && argc != 2)
                goto error;

        if (strcmp(argv[0], "flush")==0) {
                return flush_virtual_cache ( map_dev->identifier );
        } else if (strcmp(argv[0],"disable")==0) {
                put_state(map_dev->state, DISABLED);
                DPRINTK ("DISABLING! %s,%d",map_dev->vm_id,map_dev->state);
                return flush_virtual_cache ( map_dev->identifier );
        } else if (strcmp(argv[0], "enable")==0) {
                put_state(map_dev->state, ENABLED);
                DPRINTK ("ENABLING! %s,%d", map_dev->vm_id,map_dev->state);
                return 1;
        } else if (strcmp(argv[0], "share")==0) {
		sscanf(argv[1], "%d", &limit);
		map_dev->limit =  ((dmc->size * limit ) / 100);
                DPRINTK ("changing share %s,%lu", map_dev->vm_id,map_dev->limit);
                return 1;
        }

error:
        DMWARN ("unrecognised message received <%d>%s<  ",argc,argv[0]);
        return -EINVAL;
}


/****************************************************************************
 *  Functions for manipulating a cache target.
 ****************************************************************************/

static struct target_type cache_target = {
	.name   = "cache",
	.version= {1, 0, 1},
	.module = THIS_MODULE,
	.ctr    = cache_ctr,
	.dtr    = cache_dtr,
	.map    = cache_map,
	.status = cache_status,
	.message = cache_message,
};

/*
 * Initiate a cache target.
 */
int __init dm_cache_init(void)
{
	printk("INIT dm-cache!!!!!!!!!1\n");
	int r;
	r = jobs_init();
	if (r){
		DMERR("failed to initialize jobs pool");
		return r;
	}

#if WSS_ANALYSIS 
	r = wss_wq_init();
	if (r){
		DMERR("failed to initialize wss");
		return r;
	}
#endif

	_kcached_wq = create_singlethread_workqueue("kcached");
	if (!_kcached_wq) {
		DMERR("failed to start kcached");
		return -ENOMEM;
	}
	INIT_WORK(&_kcached_work, do_work);

	_kallocate_wq = create_singlethread_workqueue("kallocate");
	if (!_kallocate_wq) {
		DMERR("failed to start kallocate");
		return -ENOMEM;
	}
	INIT_WORK(&_kallocate_work, do_work_allocate);

	r = dm_register_target(&cache_target);
	if (r < 0) {
		DMERR("cache: register failed %d", r);
		destroy_workqueue(_kcached_wq);
	}

	return r;
}

/*
 * Destroy a cache target.
 */
static void __exit dm_cache_exit(void)
{
	dm_unregister_target(&cache_target);

	jobs_exit();
#if WSS_ANALYSIS 
	jobs_wss_exit();
#endif
	destroy_workqueue(_kcached_wq);
}

module_init(dm_cache_init);
module_exit(dm_cache_exit);

MODULE_DESCRIPTION(DM_NAME " cache target");
MODULE_AUTHOR("Ming Zhao <mingzhao99th@gmail.com>");
MODULE_LICENSE("GPL");
