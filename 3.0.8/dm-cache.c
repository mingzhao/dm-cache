/****************************************************************************
 *  dm-cache.c
 *  Device mapper target for block-level disk caching
 *
 *  Copyright (C) International Business Machines Corp., 2006
 *  Copyright (C) Ming Zhao, Florida International University, 2007-2009
 *
 *  Authors: Ming Zhao, Stephen Bromfield, Douglas Otstott,
 *    Dulcardo Arteaga (dm-cache@googlegroups.com)
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
#include <linux/blk_types.h>
#include <linux/atomic.h>
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
#include "dm.h"
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>

#define DMC_DEBUG 1

#define DM_MSG_PREFIX "cache"
#define DMC_PREFIX "dm-cache: "

#if DMC_DEBUG
#define DPRINTK( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

int counter_map;
int	dm_dev_identifier = 0;
struct 	dm_dev dev_arr[8];  
int    bio_in_progress = 0;

/* Default cache parameters */
#define DEFAULT_CACHE_SIZE	65536
#define DEFAULT_CACHE_ASSOC	1024
#define DEFAULT_BLOCK_SIZE	8
#define CONSECUTIVE_BLOCKS	512

/* Write policy */
#define WRITE_THROUGH 0
#define WRITE_BACK 1
#define DEFAULT_WRITE_POLICY WRITE_THROUGH

/* Number of pages for I/O */
#define DMCACHE_COPY_PAGES 1024

/* States of a cache block */
#define INVALID		0
#define VALID		1	/* Valid */
#define RESERVED	2	/* Allocated but data not in place yet */
#define DIRTY		4	/* Locally modified */
#define WRITEBACK	8	/* In the process of write back */
#define WRITETHROUGH	16	/* In the process of write back */

#define READY           0
#define PENDING_WRITE   1
#define PENDING_READ    2

#define is_state(x, y)		(x & y)
#define set_state(x, y)		(x |= y)
#define clear_state(x, y)	(x &= ~y)

/*
 * Cache context
 */
struct cache_c {
	struct dm_dev *src_dev;		/* Source device */
	struct dm_dev *cache_dev;	/* Cache device */
	struct dm_kcopyd_client *kcp_client; /* Kcopyd client for writing back data */

	struct cacheblock *cache;	/* Hash table for cache blocks */
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
	atomic_t nr_jobs;		/* Number of I/O jobs */
	struct dm_io_client *io_client;   /* Client memory pool*/

	/* Stats */
	unsigned long reads;		/* Number of reads */
	unsigned long writes;		/* Number of writes */
	unsigned long cache_hits;	/* Number of cache hits */
	unsigned long replace;		/* Number of cache replacements */
	unsigned long writeback;	/* Number of replaced dirty blocks */
	unsigned long dirty;		/* Number of submitted dirty blocks */
};

/* Cache block metadata structure */
struct cacheblock {
	spinlock_t lock;	/* Lock to protect operations on the bio list */
	sector_t block;		/* Sector number of the cached block */
	unsigned short state;	/* State of a block */
	unsigned short status; 
	unsigned long counter;	/* Logical timestamp of the block's last access */
	struct bio_list bios;	/* List of pending bios */
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
	int hit;
	/*
	 * When the original bio is not aligned with cache blocks,
	 * we need extra bvecs and pages for padding.
	 */
	struct bio_vec *bvec;
	unsigned int nr_pages;
	struct page_list *pages;
};


static int cache_insert(struct cache_c *dmc, sector_t block,sector_t cache_block); 
static int cache_read_hit(struct cache_c *dmc, struct bio* bio,sector_t cache_block);
static int cache_write_cache(struct cache_c *dmc, struct bio* bio, sector_t cache_block,
                                int hit, int writethrough);


/****************************************************************************
 *  Wrapper functions for using the new dm_io API
 ****************************************************************************/
static int dm_io_sync_vm(unsigned int num_regions, struct dm_io_region
	*where, int rw, void *data, unsigned long *error_bits, struct cache_c *dmc)
{
	struct dm_io_request iorq;

	iorq.bi_rw= rw;
	iorq.mem.type = DM_IO_VMA;
	iorq.mem.ptr.vma = data;
	iorq.notify.fn = NULL;
	iorq.client = dmc->io_client;

	return dm_io(&iorq, num_regions, where, error_bits);
}

static int dm_io_async_bvec(unsigned int num_regions, struct dm_io_region
	*where, int rw, struct bio_vec *bvec, io_notify_fn fn, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;
	struct dm_io_request iorq;

	iorq.bi_rw = (rw | (1 << 3));
	iorq.mem.type = DM_IO_BVEC;
	iorq.mem.ptr.bvec = bvec;
	iorq.notify.fn = fn;
	iorq.notify.context = context;
	iorq.client = dmc->io_client;

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

static struct workqueue_struct *_kcached_wq;
static struct work_struct _kcached_work;

static inline void wake(void)
{
	queue_work(_kcached_wq, &_kcached_work);
}

#define MIN_JOBS 1024

static struct kmem_cache *_job_cache;
static mempool_t *_job_pool;

static DEFINE_SPINLOCK(_job_lock);

//static DEFINE_SPINLOCK(mr_lock);
//static DEFINE_SPINLOCK(fetch_lock);
//static DEFINE_SPINLOCK(store_lock);
//static DEFINE_SPINLOCK(io_lock);
//static DEFINE_SPINLOCK(bio_lock);

unsigned long bio_flags;  

static LIST_HEAD(_complete_jobs);
static LIST_HEAD(_io_jobs);
static LIST_HEAD(_pages_jobs);

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

	DPRINTK("IOCALLBACK!!!!");
        if (error) {
                /* TODO */
                DMERR("io_callback: io error");
                return;
        }
        //just push a write if its a READ and MISS
        if (job->rw == READ && job->hit !=1) {
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
	unsigned long flags;

	//spin_lock_irqsave(&fetch_lock, flags);

	offset = (unsigned int) (bio->bi_sector & dmc->block_mask);
	head = to_bytes(offset);
	tail = to_bytes(dmc->block_size) - bio->bi_size - head;

	DPRINTK("do_fetch: %llu(%llu->%lu,%llu), head:%u,tail:%u",
	        (unsigned long long)bio->bi_sector, (unsigned long long)job->src.sector, 
		(unsigned long)job->dest.sector,
	        (unsigned long long)job->src.count, head, tail);

	if (bio_data_dir(bio) == READ) { /* The original request is a READ */
		if (0 == job->nr_pages) { /* The request is aligned to cache block */
			r = dm_io_async_bvec(1, &job->src, READ,
			                     bio->bi_io_vec + bio->bi_idx,
			                     io_callback, job);
	//spin_unlock_irqrestore(&fetch_lock, flags);
			return r;
		}
	
		nr_vecs = bio->bi_vcnt - bio->bi_idx + job->nr_pages;
		bvec = kmalloc(nr_vecs * sizeof(*bvec), GFP_NOIO);
		if (!bvec) {
			DMERR("do_fetch: No memory");
	//spin_unlock_irqrestore(&fetch_lock, flags);
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
	//spin_unlock_irqrestore(&fetch_lock, flags);
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
	//spin_unlock_irqrestore(&fetch_lock, flags);
			return r;
		}

		bvec = kmalloc((job->nr_pages + bio->bi_vcnt - bio->bi_idx)
				* sizeof(*bvec), GFP_KERNEL);
		if (!bvec) {
			DMERR("do_fetch: No memory");
	//spin_unlock_irqrestore(&fetch_lock, flags);
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
		printk("do_fetch end");

//	spin_unlock_irqrestore(&fetch_lock, flags);
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
	struct bio *bio = job->bio, *clone;
	struct cache_c *dmc = job->dmc;
	unsigned int offset, head, tail, remaining, nr_vecs;
	struct bio_vec *bvec;
	unsigned long flags;

	//spin_lock_irqsave(&store_lock, flags);

	offset = (unsigned int) (bio->bi_sector & dmc->block_mask);
	head = to_bytes(offset);
	tail = to_bytes(dmc->block_size) - bio->bi_size - head;

	DPRINTK("do_store: %llu(%llu->%llu,%llu), head:%u,tail:%u",
	        bio->bi_sector, job->src.sector, job->dest.sector,
	        job->src.count, head, tail);

	/* A READ is acknowledged as soon as the requested data is fetched, and
	   does not have to wait for it being stored in cache. The bio is cloned
	   so that the original one can be ended here. But to avoid copying
	   pages, we reuse the pages allocated for the original bio, and mark
	   each of them to prevent the pages being freed before the cache
	   insertion is completed.
	 */
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

	if (0 == job->nr_pages) /* Original request is aligned with cache blocks */
		r = dm_io_async_bvec(1, &job->dest, WRITE, bio->bi_io_vec + bio->bi_idx,
		                     io_callback, job);
	else {
		if (bio_data_dir(bio) == WRITE && head > 0 && tail > 0) {
			DPRINTK("Special case: %lu %u %u", bio_data_dir(bio), head, tail);
			nr_vecs = job->nr_pages + bio->bi_vcnt - bio->bi_idx;
			if (offset && (offset + bio->bi_size < PAGE_SIZE)) nr_vecs++;
			DPRINTK("Create %u new vecs", nr_vecs);
			bvec = kmalloc(nr_vecs * sizeof(*bvec), GFP_KERNEL);
			if (!bvec) {
				DMERR("do_store: No memory");
	//spin_unlock_irqrestore(&store_lock, flags);
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

		r = dm_io_async_bvec(1, &job->dest, WRITE, job->bvec, io_callback, job);
	}
	//spin_unlock_irqrestore(&store_lock, flags);
	return r;
}

int do_io(struct kcached_job *job)
{
	int r = 0;

	unsigned long flags;
	//spin_lock_irqsave(&io_lock, flags);
	if (job->rw == READ) { /* Read from source device */
		r = do_fetch(job);
	} else { /* Write to cache device */
		r = do_store(job);
	}
	//spin_unlock_irqrestore(&io_lock, flags);

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
	//do_io(job);
	return 0;
}

/*
 * Flush the bios that are waiting for this cache insertion or write back.
 */
static void flush_bios(struct cacheblock *cacheblock)
{
	struct bio *bio;
	struct bio *n;

	spin_lock(&cacheblock->lock);
	bio = bio_list_get(&cacheblock->bios);
	if (is_state(cacheblock->state, WRITEBACK)) { /* Write back finished */
		cacheblock->state = VALID;
	}else if (is_state(cacheblock->state, WRITETHROUGH)) { 
		cacheblock->state = INVALID;
		DPRINTK("WRITETHROUGH STATE ");
	}else { /* Cache insertion finished */
		set_state(cacheblock->state, VALID);
		clear_state(cacheblock->state, RESERVED);
	}
	spin_unlock(&cacheblock->lock);

	while (bio) {
		n = bio->bi_next;
		bio->bi_next = NULL;
		DPRINTK("Flush bio: %llu->%llu (%u bytes)",
		       (unsigned long long) cacheblock->block, bio->bi_sector, bio->bi_size);
		generic_make_request(bio);
		bio = n;
	}
}

static int do_complete(struct kcached_job *job)
{
        int i, r = 0;
        struct bio *bio = job->bio;

        DPRINTK("do_complete: %llu", bio->bi_sector);

        if(bio_data_dir(bio) == READ && job->hit == 1 ){
                for (i=bio->bi_idx; i<bio->bi_vcnt; i++) {
                        get_page(bio->bi_io_vec[i].bv_page);
                }
                bio_endio(bio,0);
        }

        if (bio_data_dir(bio) == READ) {
                for (i=bio->bi_idx; i<bio->bi_vcnt; i++) {
                        put_page(bio->bi_io_vec[i].bv_page);
                }
                if(job->hit != 1 )
                        bio_put(bio);
        } else
                bio_endio(bio, 0);
        if (job->nr_pages > 0) {
                kfree(job->bvec);
                kcached_put_pages(job->dmc, job->pages);
        }

        if(job->hit != 1 )
                flush_bios(job->cacheblock);


        job->cacheblock->status = READY;

        mempool_free(job, _job_pool);

        if (atomic_dec_and_test(&job->dmc->nr_jobs))
                wake_up(&job->dmc->destroyq);

        bio_in_progress = 0;
        return r;
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

static void queue_job(struct kcached_job *job)
{
	atomic_inc(&job->dmc->nr_jobs);
	if (job->nr_pages > 0) /* Request pages */
		push(&_pages_jobs, job);
	else /* Go ahead to do I/O */{
	//	spin_lock_irqsave(&bio_lock, bio_flags);

		while (bio_in_progress == 1) {
                        schedule();
                }
                bio_in_progress = 1 ;

		push(&_io_jobs, job);
	}
	//	do_io(job);
		
	wake();
}

static int kcached_init(struct cache_c *dmc)
{
	int r;

	spin_lock_init(&dmc->lock);
	dmc->pages = NULL;
	dmc->nr_pages = dmc->nr_free_pages = 0;
	r = alloc_bio_pages(dmc, DMCACHE_COPY_PAGES);
	if (r) {
		DMERR("kcached_init: Could not allocate bio pages");
		return r;
	}

	init_waitqueue_head(&dmc->destroyq);
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
	struct cacheblock *cacheblock = (struct cacheblock *) context;

	flush_bios(cacheblock);
}

static void copy_block(struct cache_c *dmc, struct dm_io_region src,
	                   struct dm_io_region dest, struct cacheblock *cacheblock)
{
	DPRINTK("Copying: %llu:%llu->%llu:%llu",
			src.sector, src.count * 512, dest.sector, dest.count * 512);
	dm_kcopyd_copy(dmc->kcp_client, &src, 1, &dest, 0, \
			(dm_kcopyd_notify_fn) copy_callback, (void *)cacheblock);
}

static void write_back(struct cache_c *dmc, sector_t index, unsigned int length)
{
	struct dm_io_region src, dest;
	struct cacheblock *cacheblock = &dmc->cache[index];
	unsigned int i;

	DPRINTK("Write back block %llu(%llu, %u)",
	        index, cacheblock->block, length);
	src.bdev = dmc->cache_dev->bdev;
	src.sector = index << dmc->block_shift;
	src.count = dmc->block_size * length;
	dest.bdev = dmc->src_dev->bdev;
	dest.sector = cacheblock->block;
	dest.count = dmc->block_size * length;

	for (i=0; i<length; i++)
		set_state(dmc->cache[index+i].state, WRITEBACK);
	dmc->dirty_blocks -= length;
	copy_block(dmc, src, dest, cacheblock);
}


/****************************************************************************
 *  Functions for implementing the various cache operations.
 ****************************************************************************/

/*
 * Map a block from the source device to a block in the cache device.
 */
static unsigned long hash_block(struct cache_c *dmc, sector_t block)
{
	unsigned long set_number, value;

	value = (unsigned long)(block >> (dmc->block_shift +
	        dmc->consecutive_shift));
	set_number = hash_long(value, dmc->bits) / dmc->assoc;

 	return set_number;
}

/*
 * Reset the LRU counters (the cache's global counter and each cache block's
 * counter). This seems to be a naive implementaion. However, consider the
 * rareness of this event, it might be more efficient that other more complex
 * schemes. TODO: a more elegant solution.
 */
static void cache_reset_counter(struct cache_c *dmc)
{
	sector_t i;
	struct cacheblock *cache = dmc->cache;

	DPRINTK("Reset LRU counters");
	for (i=0; i<dmc->size; i++)
		cache[i].counter = 0;

	dmc->counter = 0;
}

struct ext_sector {
 	sector_t block:58;
 	sector_t disk:6;
};


/*
 * Lookup a block in the cache.
 *
 * Return value:
 *  1: cache hit (cache_block stores the index of the matched block)
 *  0: cache miss but frame is allocated for insertion; cache_block stores the
 *     frame's index:
 *      If there are empty frames, then the first encounted is used.
 *      If there are clean frames, then the LRU clean block is replaced.
 *  2: cache miss and frame is not allocated; cache_block stores the LRU dirty
 *     block's index:
 *      This happens when the entire set is dirty.
 * -1: cache miss and no room for insertion:
 *      This happens when the entire set in transition modes (RESERVED or
 *      WRITEBACK).
 *
 */
static int cache_lookup(struct cache_c *dmc, sector_t block_in,
 	                    sector_t *cache_block, int disk,int noalloc)
{

        sector_t block_ori = block_in;

        struct ext_sector *blockst = (struct ext_sector*) &block_in;
        blockst->disk = disk;
        sector_t block = *(sector_t *)blockst;


//	unsigned long set_number = hash_block(dmc, block);
	block = block_ori;
	unsigned long set_number = block_ori;

	sector_t index;
	int i, res;
	unsigned int cache_assoc = dmc->assoc;
	struct cacheblock *cache = dmc->cache;
	int invalid = -1, oldest = -1, oldest_clean = -1;
	unsigned long counter = ULONG_MAX, clean_counter = ULONG_MAX;


	index=set_number * cache_assoc;
//	index = block_ori ;

	BUG_ON(index > dmc->size);
/*
	DPRINTK("BEFORE   INDEX NUL!!!!!!!!!!!!!!!!");
	if(cache[index].state != 0)
		DPRINTK("INDEX NUL!!!!!!!!!!!!!!!!");
	DPRINTK("AFTER ---  INDEX NUL!!!!!!!!!!!!!!!!");
*/		

	for (i=0; i<cache_assoc; i++, index++) {
		if (is_state(cache[index].state, VALID) ||
		    is_state(cache[index].state, RESERVED)) {
			if (cache[index].block == block_ori) {
				*cache_block = index;
				/* Reset all counters if the largest one is going to overflow */
				if (dmc->counter == ULONG_MAX) cache_reset_counter(dmc);
				cache[index].counter = ++dmc->counter;
				break;
			} else {
				/* Don't consider blocks that are in the middle of copying */
				if (!is_state(cache[index].state, RESERVED) &&
				    !is_state(cache[index].state, WRITEBACK)) {
					if (!is_state(cache[index].state, DIRTY) &&
					    cache[index].counter < clean_counter) {
						clean_counter = cache[index].counter;
						oldest_clean = i;
					}
					if (cache[index].counter < counter) {
						counter = cache[index].counter;
						oldest = i;
					}
				}
			}
		} else {
			if (-1 == invalid) invalid = i;
		}
	}

	res = i < cache_assoc ? 1 : 0;
	if (!res) { /* Cache miss */
//  	        if (noalloc == 1) return 0;
		if (invalid != -1) /* Choose the first empty frame */
//			*cache_block = set_number * cache_assoc + invalid;
			*cache_block = block_ori;
		else if (oldest_clean != -1) /* Choose the LRU clean block to replace */
//			*cache_block = set_number * cache_assoc + oldest_clean;
			*cache_block = block_ori;
		else if (oldest != -1) { /* Choose the LRU dirty block to evict */
			res = 2;
//			*cache_block = set_number * cache_assoc + oldest;
			*cache_block = block_ori;
		} else {
			res = -1;
		}
	}

	if (-1 == res)
		DPRINTK("Cache lookup: Block %llu(%lu):%s",
	            block, set_number, "NO ROOM");
	else
		DPRINTK("Cache lookup: Block %llu(%lu):%llu(%s)",
		        block, set_number, *cache_block,
		        1 == res ? "HIT" : (0 == res ? "MISS" : "WB NEEDED"));
	return res;
}

/*
 * Insert a block into the cache (in the frame specified by cache_block).
 */
static int cache_insert(struct cache_c *dmc, sector_t block,
	                    sector_t cache_block)
{
	struct cacheblock *cache = dmc->cache;

	/* Mark the block as RESERVED because although it is allocated, the data are
       not in place until kcopyd finishes its job.
	 */
	cache[cache_block].block = block;
	cache[cache_block].state = RESERVED;
	if (dmc->counter == ULONG_MAX) cache_reset_counter(dmc);
	cache[cache_block].counter = ++dmc->counter;

	return 1;
}

/*
 * Invalidate a block (specified by cache_block) in the cache.
 */
static void cache_invalidate(struct cache_c *dmc, sector_t cache_block)
{
	struct cacheblock *cache = dmc->cache;

	DPRINTK("Cache invalidate: Block %llu(%llu)",
	        cache_block, cache[cache_block].block);
	clear_state(cache[cache_block].state, VALID);
}

/*
 * Handle a cache hit:
 *  For READ, serve the request from cache is the block is ready; otherwise,
 *  queue the request for later processing.
 *  For write, invalidate the cache block if write-through. If write-back,
 *  serve the request from cache if the block is ready, or queue the request
 *  for later processing if otherwise.
 */
static int cache_hit(struct cache_c *dmc, struct bio* bio, sector_t cache_block)
{
	unsigned int offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
	struct cacheblock *cache = dmc->cache;

	dmc->cache_hits++;

	if (bio_data_dir(bio) == READ) { /* READ hit */
		bio->bi_bdev = dmc->cache_dev->bdev;
		bio->bi_sector = (cache_block << dmc->block_shift)  + offset;
		bio->bi_sector = cache_block ;
	
     return cache_read_hit(dmc,bio,cache_block);

/*		spin_lock(&cache[cache_block].lock);

		if (is_state(cache[cache_block].state, VALID)) { // Valid cache block 
			spin_unlock(&cache[cache_block].lock);
			
			DPRINTK("VALID!!! %llu:%llu",cache_block,bio->bi_sector);
			return 1;
		}

		// Cache block is not ready yet 
		DPRINTK("Add to bio list %s(%llu)",
				dmc->cache_dev->name, bio->bi_sector);
		bio_list_add(&cache[cache_block].bios, bio);

		spin_unlock(&cache[cache_block].lock);
		DPRINTK("Add1 to bio list %s(%llu)",
				dmc->cache_dev->name, bio->bi_sector);
		return 0;*/
	} else { /* WRITE hit */
		if (dmc->write_policy == WRITE_THROUGH) { /* Invalidate cached data */
			if (is_state(cache[cache_block].state, VALID)) {
				DPRINTK("WRITE THROUGH VALID!!!");
				cache_invalidate(dmc, cache_block);
				bio->bi_bdev = dmc->src_dev->bdev;
				return cache_write_cache(dmc, bio,cache_block,1,1);
//				return 1;
			}
			
				DPRINTK("WRITE THROUGH INVALID!!!");
				set_state(cache[cache_block].state,WRITETHROUGH);
				bio_list_add(&cache[cache_block].bios, bio);
				return 0;
			
		}

		/* Write delay */
		if (!is_state(cache[cache_block].state, DIRTY)) {
			set_state(cache[cache_block].state, DIRTY);
			dmc->dirty_blocks++;
		}

		spin_lock(&cache[cache_block].lock);

 		/* In the middle of write back */
		if (is_state(cache[cache_block].state, WRITEBACK)) {
			/* Delay this write until the block is written back */
			bio->bi_bdev = dmc->src_dev->bdev;
			DPRINTK("Add to bio list %s(%llu)",
					dmc->src_dev->name, bio->bi_sector);
			bio_list_add(&cache[cache_block].bios, bio);
			spin_unlock(&cache[cache_block].lock);
			return 0;
		}

		/* Cache block not ready yet */
		if (is_state(cache[cache_block].state, RESERVED)) {
			bio->bi_bdev = dmc->cache_dev->bdev;
			bio->bi_sector = (cache_block << dmc->block_shift) + offset;
			DPRINTK("Add to bio list %s(%llu)",
					dmc->cache_dev->name, bio->bi_sector);
			bio_list_add(&cache[cache_block].bios, bio);
			spin_unlock(&cache[cache_block].lock);
			return 0;
		}

		/* Serve the request from cache */
		bio->bi_bdev = dmc->cache_dev->bdev;
		bio->bi_sector = (cache_block << dmc->block_shift) + offset;

		spin_unlock(&cache[cache_block].lock);
		return cache_write_cache(dmc, bio,cache_block,1,0);
	}
}

static struct kcached_job *new_kcached_job(struct cache_c *dmc, struct bio* bio,
	                                       sector_t request_block,
                                           sector_t cache_block)
{
	struct dm_io_region src, dest;
	struct kcached_job *job;

	src.bdev = dmc->src_dev->bdev;
	src.sector = request_block;
	src.count = dmc->block_size;
	dest.bdev = dmc->cache_dev->bdev;
	//dest.sector = cache_block << dmc->block_shift;
	dest.sector = cache_block;

	dest.count = src.count;

	job = mempool_alloc(_job_pool, GFP_NOIO);
	job->dmc = dmc;
	job->bio = bio;
	job->src = src;
	job->dest = dest;
	job->cacheblock = &dmc->cache[cache_block];

	return job;
}

/*
 * Handle a read cache miss:
 *  Update the metadata; fetch the necessary block from source device;
 *  store data to cache device.
 */
static int cache_read_miss(struct cache_c *dmc, struct bio* bio,
	                       sector_t cache_block) {
	struct cacheblock *cache = dmc->cache;
	unsigned int offset, head, tail;
	struct kcached_job *job;
	sector_t request_block, left;

	offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
	request_block = bio->bi_sector - offset;

	if (cache[cache_block].state & VALID) {
		DPRINTK("Replacing %llu->%llu",
		        cache[cache_block].block, request_block);
		dmc->replace++;
	} else DPRINTK("Insert block %llu at empty frame %llu",
		request_block, cache_block);


	cache_insert(dmc, request_block, cache_block); /* Update metadata first */
	job = new_kcached_job(dmc, bio, request_block, cache_block);

	head = to_bytes(offset);

	left = (dmc->src_dev->bdev->bd_inode->i_size>>9) - request_block;
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
	job->hit = 0;

	BUG_ON(job->nr_pages != 0); // should be aligned
	DPRINTK("Queue job for %llu (need %u pages)",
	        bio->bi_sector, job->nr_pages);
	queue_job(job);
	//do_pages(job);
	//do_io(job);

	return 0;
}
/*
 * Handle a read cache hit:
 *  fetch the necessary block from cache device;
 *  restore, do not do store, just jumpt directly to do_complete
 *  
 */
static int cache_read_hit(struct cache_c *dmc, struct bio* bio,
                               sector_t cache_block) {
        DPRINTK("CACHE_READ_HIT!!!!");
        struct cacheblock *cache = dmc->cache;
        unsigned int offset, head, tail;
        struct kcached_job *job;
        sector_t request_block, left;

        offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
        request_block = bio->bi_sector - offset;

        if (cache[cache_block].state & VALID) {
                DPRINTK("Hit Read been processed %llu->%llu",
                        cache[cache_block].block, request_block);
        } else{
                DPRINTK("Something is wrong here %llu at empty frame %llu",
                request_block, cache_block);
        //      BUG_ON(1);
        }
        struct dm_io_region src;
        src.bdev =  dmc->cache_dev->bdev;
        src.sector = cache_block;
        src.count = dmc->block_size;

        job = mempool_alloc(_job_pool, GFP_NOIO);
        job->dmc = dmc;
        job->bio = bio;
        job->src = src;
        job->cacheblock = &dmc->cache[cache_block];

//---------------------------------
        head = to_bytes(offset);

        left = (dmc->src_dev->bdev->bd_inode->i_size>>9) - request_block;
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
        job->hit = 1;

//        while(cache[cache_block].status != READY){
  //              schedule();
    //    }
        cache[cache_block].status = PENDING_READ;

       // BUG_ON(job->nr_pages != 0); // should be aligned
        DPRINTK("Queue job for %llu (need %u pages)",
                bio->bi_sector, job->nr_pages);
        queue_job(job);

        return 0;
}

/*
 * Handle a write cache hit:
 */
static int cache_write_cache(struct cache_c *dmc, struct bio* bio, sector_t cache_block,
                                int hit, int writethrough) {
        struct cacheblock *cache = dmc->cache;
        unsigned int offset, head, tail;
        struct kcached_job *job;
        sector_t request_block, left;


        offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
        request_block = bio->bi_sector - offset;

        if (cache[cache_block].state & VALID) {
                DPRINTK("WRITE THROUGH MISS .VALID  %llu->%llu",
                        cache[cache_block].block, request_block);
                dmc->replace++;
        } else DPRINTK("WRITE THROUG MISS INVALID request: %llu cache block %llu",
                request_block, cache_block);

        /* Write delay */
        //cache_insert(dmc, request_block, cache_block); /* Update metadata first */
        //set_state(cache[cache_block].state, DIRTY);
        //dmc->dirty_blocks++;
//------------job-------------------------
//      job = new_kcached_job(dmc, bio, request_block, cache_block);

        struct dm_io_region dest;
        if(writethrough)
                dest.bdev = dmc->src_dev->bdev;
        else
                dest.bdev = dmc->cache_dev->bdev;

        dest.sector = bio->bi_sector;

        dest.count = dmc->block_size;
        job = mempool_alloc(_job_pool, GFP_NOIO);
        job->dmc = dmc;
        job->bio = bio;
        job->dest = dest;
        job->cacheblock = &dmc->cache[cache_block];
        job->hit = hit ;

//----------------------------------------------
        head = to_bytes(offset);
        left = (dmc->src_dev->bdev->bd_inode->i_size>>9) - request_block;
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
 //       while(cache[cache_block].status != READY){
   //             schedule();
     //   }
        cache[cache_block].status = PENDING_WRITE;

        queue_job(job);

        return 0;
}



/*
 * Handle a write cache miss:
 *  If write-through, forward the request to source device.
 *  If write-back, update the metadata; fetch the necessary block from source
 *  device; write to cache device.
 */
static int cache_write_miss(struct cache_c *dmc, struct bio* bio, sector_t cache_block) {
	struct cacheblock *cache = dmc->cache;
	unsigned int offset, head, tail;
	struct kcached_job *job;
	sector_t request_block, left;

	if (dmc->write_policy == WRITE_THROUGH) { /* Forward request to souuce */
		bio->bi_bdev = dmc->src_dev->bdev;
		return cache_write_cache(dmc, bio,cache_block,0,1);
	}

	offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
	request_block = bio->bi_sector - offset;

	if (cache[cache_block].state & VALID) {
		DPRINTK("Replacing %llu->%llu",
		        cache[cache_block].block, request_block);
		dmc->replace++;
	} else DPRINTK("Insert block %llu at empty frame %llu",
		request_block, cache_block);

	/* Write delay */
	cache_insert(dmc, request_block, cache_block); /* Update metadata first */
	set_state(cache[cache_block].state, DIRTY);
	dmc->dirty_blocks++;

	job = new_kcached_job(dmc, bio, request_block, cache_block);

	head = to_bytes(offset);
	left = (dmc->src_dev->bdev->bd_inode->i_size>>9) - request_block;
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
static int cache_miss(struct cache_c *dmc, struct bio* bio, sector_t cache_block) {
	if (bio_data_dir(bio) == READ)
		return cache_read_miss(dmc, bio, cache_block);
	else
		return cache_write_miss(dmc, bio, cache_block);
}



static int get_disk_identifier (struct cache_c *dmc)
{
 	int i, ret = 0;
 	for (i = 0 ; i < dm_dev_identifier ; i++){
 		if(dev_arr->bdev->bd_dev == dmc->src_dev->bdev->bd_dev)
 			ret = i;
 	}
 	DPRINTK("SOURCE: %llu ret: %d",dmc->src_dev->bdev->bd_dev,ret);
 	return ret;
}


/****************************************************************************
 *  Functions for implementing the operations on a cache mapping.
 ****************************************************************************/

/*
 * Decide the mapping and perform necessary cache operations for a bio request.
 */
static int cache_map(struct dm_target *ti, struct bio *bio,
		      union map_info *map_context)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	sector_t request_block, cache_block = 0, offset;
	int res,ret = 1 ;
	int noalloc = 0;
	unsigned long flags;

//	spin_lock_irqsave(&mr_lock, flags);


	offset = bio->bi_sector & dmc->block_mask;
	request_block = bio->bi_sector - offset;

	DPRINTK("Got a %s for %llu ((%llu:%llu), %u bytes)",
	        bio_rw(bio) == WRITE ? "WRITE" : (bio_rw(bio) == READ ?
	        "READ":"READA"), bio->bi_sector, request_block, offset,
	        bio->bi_size);
	DPRINTK("Counter_map: %d",++counter_map);

	if (bio_data_dir(bio) == READ) dmc->reads++;
	else dmc->writes++;

	int disk = get_disk_identifier(dmc);

	/* WRITE_THROUGH does not need a cache_block */
	if (dmc->write_policy == WRITE_THROUGH && bio_rw(bio) == WRITE)
               noalloc = 1;


	res = cache_lookup(dmc, request_block, &cache_block,disk,noalloc);
        DPRINTK("SECTOR: REQ:%llu | MAP:%llu Res: %llu:%llu",bio->bi_sector, request_block,res,noalloc);
//	res = 0;
	if (1 == res)  /* Cache hit; server request from cache */
		return  cache_hit(dmc, bio, cache_block);
	else if (0 == res) /* Cache miss; replacement block is found */
		return  cache_miss(dmc, bio, cache_block);
	else if (2 == res) { /* Entire cache set is dirty; initiate a write-back */
		write_back(dmc, cache_block, 1);
		dmc->writeback++;
	}else {
		/* Forward to source device */
		bio->bi_bdev = dmc->src_dev->bdev;
	}
//	spin_unlock_irqrestore(&mr_lock, flags);

	return ret;
}

struct meta_dmc {
	sector_t size;
	unsigned int block_size;
	unsigned int assoc;
	unsigned int write_policy;
	unsigned int chksum;
};

/* Load metadata stored by previous session from disk. */
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
	/* When requesting a new bio, the number of requested bvecs has to be
	   less than BIO_MAX_PAGES. Otherwise, null is returned. In dm-io.c,
	   this return value is not checked and kernel Oops may happen. We set
	   the limit here to avoid such situations. (2 additional bvecs are
	   required by dm-io for bookeeping.)
	 */
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

	if (chksum != chksum_sav) { /* Check the checksum of the metadata */
		DPRINTK("Cache metadata loaded from disk is corrupted");
		vfree((void *)dmc->cache);
		return 1;
	}

	DMINFO("Cache metadata loaded from disk (offset %llu)",
	       (unsigned long long) dev_size - 1 - (unsigned long long) meta_size);;

	return 0;
}

/* Store metadata onto disk. */
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
			/* Assume all invalid cache blocks store 0. We lose the block that
			 * is actually mapped to offset 0.
			 */
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
 */
static int cache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct cache_c *dmc;
	unsigned int consecutive_blocks, persistence = 0;
	sector_t localsize, i, order;
	sector_t data_size, meta_size, dev_size;
	unsigned long long cache_size;
	int r = -EINVAL;

	if (argc < 2) {
		ti->error = "dm-cache: Need at least 2 arguments (src dev and cache dev)";
		goto bad;
	}

	dmc = kmalloc(sizeof(*dmc), GFP_KERNEL);
	if (dmc == NULL) {
		ti->error = "dm-cache: Failed to allocate cache context";
		r = ENOMEM;
		goto bad;
	}

	r = dm_get_device(ti, argv[0],
			  dm_table_get_mode(ti->table), &dmc->src_dev);
	if (r) {
		ti->error = "dm-cache: Source device lookup failed";
		goto bad1;
	}else {
	        dev_arr[dm_dev_identifier++] = *dmc->src_dev;
	}

	r = dm_get_device(ti, argv[1],
			  dm_table_get_mode(ti->table), &dmc->cache_dev);
	if (r) {
		ti->error = "dm-cache: Cache device lookup failed";
		goto bad2;
	}

	dmc->io_client = dm_io_client_create();
	if (IS_ERR(dmc->io_client)) {
		r = PTR_ERR(dmc->io_client);
		ti->error = "Failed to create io client\n";
		goto bad3;
	}

	dmc->kcp_client = dm_kcopyd_client_create();
	if (dmc->kcp_client == NULL) {
		ti->error = "Failed to initialize kcopyd client\n";
		goto bad4;
	}

	r = kcached_init(dmc);
	if (r) {
		ti->error = "Failed to initialize kcached";
		goto bad5;
	}

	if (argc >= 3) {
		if (sscanf(argv[2], "%u", &persistence) != 1) {
			ti->error = "dm-cache: Invalid cache persistence";
			r = -EINVAL;
			goto bad6;
		}
	}
	if (1 == persistence) {
		if (load_metadata(dmc)) {
			ti->error = "dm-cache: Invalid cache configuration";
			r = -EINVAL;
			goto bad6;
		}
		goto init; /* Skip reading cache parameters from command line */
	} else if (persistence != 0) {
			ti->error = "dm-cache: Invalid cache persistence";
			r = -EINVAL;
			goto bad6;
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
		if (!dmc->size || (dmc->size & (dmc->size - 1))) {
			ti->error = "dm-cache: Invalid cache size";
			r = -EINVAL;
			goto bad6;
		}
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
	meta_size = dm_div_up(dmc->size * sizeof(sector_t), 512) + 1;

	if ((data_size + meta_size) > dev_size) {
		DMERR("Requested cache size exeeds the cache device's capacity" \
		      "(%llu+%llu>%llu)",
  		      (unsigned long long) data_size, (unsigned long long) meta_size,
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
		if (dmc->write_policy != 0 && dmc->write_policy != 1) {
			ti->error = "dm-cache: Invalid cache write policy";
			r = -EINVAL;
			goto bad6;
		}
	} else
		dmc->write_policy = DEFAULT_WRITE_POLICY;

	dmc->size = 6291456ull;
	order = dmc->size * sizeof(struct cacheblock);
	localsize = data_size >> 11;
	DMINFO("Allocate %lluKB (%luB per) mem for %llu-entry cache" \
	       "(capacity:%lluMB, associativity:%u, block size:%u " \
	       "sectors(%uKB), %s)",
	       (unsigned long long) order >> 10, (unsigned long) sizeof(struct cacheblock),
	       (unsigned long long) dmc->size,
	       (unsigned long long) data_size >> (20-SECTOR_SHIFT),
	       dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT),
	       dmc->write_policy ? "write-back" : "write-through");

	dmc->cache = (struct cacheblock *)vmalloc(order);
	if (!dmc->cache) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		goto bad6;
	}

init:	/* Initialize the cache structs */
	for (i=0; i<dmc->size; i++) {
		bio_list_init(&dmc->cache[i].bios);
		if(!persistence) dmc->cache[i].state = 0;
		dmc->cache[i].state = 0;
		dmc->cache[i].status = 0;
		dmc->cache[i].counter = 0;
		spin_lock_init(&dmc->cache[i].lock);
	}

	dmc->counter = 0;
	dmc->dirty_blocks = 0;
	dmc->reads = 0;
	dmc->writes = 0;
	dmc->cache_hits = 0;
	dmc->replace = 0;
	dmc->writeback = 0;
	dmc->dirty = 0;

	ti->split_io = dmc->block_size;
	ti->private = dmc;
	return 0;

bad6:
	kcached_client_destroy(dmc);
bad5:
	dm_kcopyd_client_destroy(dmc->kcp_client);
bad4:
	dm_io_client_destroy(dmc->io_client);
bad3:
	dm_put_device(ti, dmc->cache_dev);
bad2:
	dm_put_device(ti, dmc->src_dev);
bad1:
	kfree(dmc);
bad:
	return r;
}


static void cache_flush(struct cache_c *dmc)
{
	struct cacheblock *cache = dmc->cache;
	sector_t i = 0;
	unsigned int j;

	DMINFO("Flush dirty blocks (%llu) ...", (unsigned long long) dmc->dirty_blocks);
	while (i< dmc->size) {
		j = 1;
		if (is_state(cache[i].state, DIRTY)) {
			while ((i+j) < dmc->size && is_state(cache[i+j].state, DIRTY)
			       && (cache[i+j].block == cache[i].block + j *
			       dmc->block_size)) {
				j++;
			}
			dmc->dirty += j;
			write_back(dmc, i, j);
		}
		i += j;
	}
}

/*
 * Destroy the cache mapping.
 */
static void cache_dtr(struct dm_target *ti)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;

	if (dmc->dirty_blocks > 0) cache_flush(dmc);

	kcached_client_destroy(dmc);

	dm_kcopyd_client_destroy(dmc->kcp_client);

	if (dmc->reads + dmc->writes > 0)
		DMINFO("stats: reads(%lu), writes(%lu), cache hits(%lu, 0.%lu)," \
		       "replacement(%lu), replaced dirty blocks(%lu), " \
	           "flushed dirty blocks(%lu)",
		       dmc->reads, dmc->writes, dmc->cache_hits,
		       dmc->cache_hits * 100 / (dmc->reads + dmc->writes),
		       dmc->replace, dmc->writeback, dmc->dirty);

	dump_metadata(dmc); /* Always dump metadata to disk before exit */
	vfree((void *)dmc->cache);
	dm_io_client_destroy(dmc->io_client);

	dm_put_device(ti, dmc->src_dev);
	dm_put_device(ti, dmc->cache_dev);
	kfree(dmc);
}

/*
 * Report cache status:
 *  Output cache stats upon request of device status;
 *  Output cache configuration upon request of table status.
 */
static int cache_status(struct dm_target *ti, status_type_t type,
			 char *result, unsigned int maxlen)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("stats: reads(%lu), writes(%lu), cache hits(%lu, 0.%lu)," \
	           "replacement(%lu), replaced dirty blocks(%lu)",
	           dmc->reads, dmc->writes, dmc->cache_hits,
	           (dmc->reads + dmc->writes) > 0 ? \
	           dmc->cache_hits * 100 / (dmc->reads + dmc->writes) : 0,
	           dmc->replace, dmc->writeback);
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("conf: capacity(%lluM), associativity(%u), block size(%uK), %s",
	           (unsigned long long) dmc->size * dmc->block_size >> 11,
	           dmc->assoc, dmc->block_size>>(10-SECTOR_SHIFT),
	           dmc->write_policy ? "write-back":"write-through");
		break;
	}
	return 0;
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
};

/*
 * Initiate a cache target.
 */
int __init dm_cache_init(void)
{
	int r;

	r = jobs_init();
	if (r)
		return r;

	_kcached_wq = create_singlethread_workqueue("kcached");
	if (!_kcached_wq) {
		DMERR("failed to start kcached");
		return -ENOMEM;
	}
	INIT_WORK(&_kcached_work, do_work);

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
	destroy_workqueue(_kcached_wq);
}

module_init(dm_cache_init);
module_exit(dm_cache_exit);

MODULE_DESCRIPTION(DM_NAME " cache target");
MODULE_AUTHOR("Ming Zhao <mingzhao99th@gmail.com>");
MODULE_LICENSE("GPL");
