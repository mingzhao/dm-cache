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
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/dm-io.h>
#include <linux/blktrace_api.h>
#include <linux/hrtimer.h>


#include "dm.h"
#include "dm-bio-list.h"
#include "kcopyd.h"

#define DMC_DEBUG 0

#define DM_MSG_PREFIX "cache"
#define DMC_PREFIX "dm-cache: "

#if DMC_DEBUG
#define DPRINTK( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

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
#define WRITETHROUGH	16	/* In the process of write through */

#define is_state(x, y)		(x & y)
#define set_state(x, y)		(x |= y)
#define clear_state(x, y)	(x &= ~y)
#define put_state(x, y)		(x = y)

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

        unsigned long reads;            /* Number of reads */
        unsigned long writes;           /* Number of writes */
        unsigned long cache_hits;       /* Number of cache hits */
        unsigned long read_hits;
        unsigned long write_hits;
        unsigned long misses;
        unsigned long read_misses;
        unsigned long write_misses;

	struct trace_c *trace;
};

struct flush{
	struct cacheblock * realblock;
	sector_t block;
	unsigned short state; 
};

struct dm_dev_internal {
	atomic_t count;
	struct dm_dev dm_dev;
};

/*
 * Cache context
 */
struct cache_c {
	struct dm_target *reboot_ti;	/* global dm_target to hold global cache */	
	struct dm_dev *src_dev;		/* Source device */
	struct dm_dev *cache_dev;	/* Cache device */
	struct kcopyd_client *kcp_client; /* Kcopyd client for writing back data */

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
	atomic_t nr_jobs;		/* Number of I/O jobs */

        /* LRU List */
        struct list_head *lru;
//	struct block_list *temp;
	struct cacheblock *blocks;
	struct semaphore lru_mutex;

	struct timer_list reboot_time;  // this timer will protec from vm being moved without removing the mapping

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
        unsigned long write_hits;

        unsigned long sequential_reads;
	unsigned long sequential_writes;
	
};

/* Cache block metadata structure */
struct cacheblock {
//	spinlock_t lock;	/* Lock to protect operations on the bio list */
	sector_t block;		/* Sector number of the cached block */
        sector_t cacheblock;

	unsigned short state;	/* State of a block */
	unsigned short disk;		/* Disk identifier for LV of each VM */
//	atomic_t status;
        struct list_head list;
};

struct bio_list bios;	/* List of pending bios */

/* Structure for a kcached job */
struct kcached_job {
	struct list_head list;
	struct cache_c *dmc;
	struct bio *bio;	/* Original bio */
	struct io_region src;
	struct io_region dest;
	struct cacheblock *cacheblock;
	int rw;
	/*
	 * When the original bio is not aligned with cache blocks,
	 * we need extra bvecs and pages for padding.
	 */
	struct bio_vec *bvec;
	unsigned int nr_pages;
	struct page_list *pages;
};

/*****************************************************************
*	Trace collector structures
******************************************************************/

#define MIN_JOBS        1024
#define MAX_SECTORS     2

static LIST_HEAD(_trace_jobs);
static DEFINE_SPINLOCK(_trace_lock);

static struct kmem_cache *_trace_cache;
static mempool_t *_trace_pool;
atomic_t nr_traces;

static struct workqueue_struct *trace_wq;
static struct work_struct trace_work;

struct trace_c {
        struct dm_dev *dev;
        struct dm_dev *trace_dev;
        sector_t trace_pos;
        sector_t trace_sector;
        void *write_buf;
        struct dm_io_client *io_client;   /* Client memory pool*/
};

struct trace_job {
        struct list_head list;
        struct blk_io_trace bit;
        struct trace_c *trace;
};

unsigned long sequence;

static const u32 ddir_act[2] = { BLK_TC_ACT(BLK_TC_READ),
                                 BLK_TC_ACT(BLK_TC_WRITE) };

#define BLK_TC_RAHEAD           BLK_TC_AHEAD

/* The ilog2() calls fall out because they're constant */
#define MASK_TC_BIT(rw, __name) ((rw & REQ_ ## __name) << \
          (ilog2(BLK_TC_ ## __name) + BLK_TC_SHIFT - __REQ_ ## __name))


static inline struct trace_job *pop_t(struct list_head *jobs)
{
        struct trace_job *job = NULL;
        unsigned long flags;

        spin_lock_irqsave(&_trace_lock, flags);

        if (!list_empty(jobs)) {
                job = list_entry(jobs->next, struct trace_job, list);
                list_del(&job->list);
        }
        spin_unlock_irqrestore(&_trace_lock, flags);

        return job;
}

static inline void push_t(struct list_head *jobs, struct trace_job *job)
{
        unsigned long flags;

        spin_lock_irqsave(&_trace_lock, flags);
        list_add_tail(&job->list, jobs);
        spin_unlock_irqrestore(&_trace_lock, flags);
}
static int process_traces(struct list_head *jobs,
                            int (*fn) (struct trace_job *))
{
        struct trace_job *job;
        int r, count = 0;

        while ((job = pop_t(jobs))) {
                r = fn(job);

                if (r < 0) {
                        /* error this rogue job */
                        DMERR("process_traces: Job processing error");
                }

                if (r > 0) {
                        /*
                         * We couldn't service this job ATM, so
                         * push this job back onto the list.
                         */
                        push_t(jobs, job);
                        break;
                }

                count++;
        }

        return count;
}
void push_trace(sector_t sector, int rw, int bytes, struct trace_c *trace)
{
        struct trace_job *trace_job;
        u32 what = BLK_TA_QUEUE;

//        what |= ddir_act[rw & WRITE];
//        what |= MASK_TC_BIT(rw, SYNC);
//        what |= MASK_TC_BIT(rw, RAHEAD);
//        what |= MASK_TC_BIT(rw, META);
//        what |= MASK_TC_BIT(rw, DISCARD);

        if(atomic_read(&nr_traces) < MIN_JOBS) {
                trace_job = mempool_alloc(_trace_pool, GFP_NOIO);
                atomic_inc(&nr_traces);
                memset(&trace_job->bit, 0, sizeof(trace_job->bit));

                trace_job->bit.magic = BLK_IO_TRACE_MAGIC | BLK_IO_TRACE_VERSION;
                trace_job->bit.sequence = ++sequence;
                trace_job->bit.time = ktime_to_ns(ktime_get_real());

                trace_job->bit.sector = sector;
                trace_job->bit.action = what;
                trace_job->bit.pdu_len = 0;
                trace_job->bit.bytes = bytes;
                trace_job->bit.device = 0;
                trace_job->bit.error = 0;

                trace_job->trace = trace;

                push_t(&_trace_jobs, trace_job);
                queue_work(trace_wq, &trace_work);
        }else {
                DPRINTK("MIN JOB REACH!!!!");
        }
}

static int write_data( struct block_device * bdev, sector_t sector,
                void * data, int count, struct dm_io_client *io_client)
{
        struct io_region where;
        unsigned long error_bits;
        int ret  = -1;

        where.sector = sector;
        where.count = count;
        where.bdev = bdev;

        DPRINTK("TRACE: writing to disk %llu",(unsigned long long) sector);
	ret = dm_io_sync_vm(1, &where, WRITE, data, &error_bits);

        return ret;
}

static int write_trace(struct trace_job * job) //struct bio *bio, struct trace_c *trace)
{
        int ret=0, size;
        struct trace_c *trace;
        int tail=0, left=0;

        trace = job->trace;

        DPRINTK("TRACE: %llu pos:%llu",(unsigned long long) job->bit.sector,
                                        (unsigned long long) trace->trace_pos);

        size = sizeof(struct blk_io_trace);

        DPRINTK("TRACE: writing to memory %llu",(unsigned long long) trace->trace_pos);
        if(trace->trace_pos + size > (MAX_SECTORS * 512)){
                tail = (MAX_SECTORS*512)-trace->trace_pos;
                left = size - tail;

                memcpy (trace->write_buf + trace->trace_pos, &job->bit, size);

                write_data(trace->trace_dev->bdev,
                                trace->trace_sector,
                                trace->write_buf,
                                MAX_SECTORS,
                                trace->io_client);
                trace->trace_pos = 0;
                trace->trace_sector += MAX_SECTORS;

                memset(trace->write_buf, 0, size);
                memmove (trace->write_buf , trace->write_buf + (MAX_SECTORS * 512), left);
                trace->trace_pos += left;
        }else{
                memcpy (trace->write_buf + trace->trace_pos , &job->bit, size);
                trace->trace_pos += size;
        }

        mempool_free(job, _trace_pool);
        atomic_dec(&nr_traces);

        return ret;
}
static void do_trace(struct work_struct *ignored)
{
        process_traces(&_trace_jobs, write_trace);
}

/*****************************************************************
*	Shared structures
******************************************************************/
struct cache_c *shared_cache;
struct v_map *virtual_mapping;

/*****************************************************************
*	Functions
******************************************************************/
static int virtual_cache_map(struct bio *bio);
static sector_t get_block_index(sector_t block, int disk);
static void reboot_map (unsigned long ptr);

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

static LIST_HEAD(_complete_jobs);
static LIST_HEAD(_io_jobs);
static LIST_HEAD(_pages_jobs);

static int jobs_init(void)
{
	_job_cache = kmem_cache_create("kcached-jobs",
	                               sizeof(struct kcached_job),
	                               __alignof__(struct kcached_job),
	                               0, NULL,NULL);
	if (!_job_cache)
		return -ENOMEM;

	_job_pool = mempool_create(MIN_JOBS, mempool_alloc_slab,
	                           mempool_free_slab, _job_cache);
	if (!_job_pool) {
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}

        _trace_cache = kmem_cache_create("trace-jobs",
                                       sizeof(struct trace_job),
                                       __alignof__(struct trace_job),
                                       0, NULL,NULL);
        if (!_trace_cache)
                return -ENOMEM;

        atomic_set(&nr_traces, 0);

        _trace_pool = mempool_create(MIN_JOBS, mempool_alloc_slab,
                                   mempool_free_slab, _trace_cache);
        if (!_trace_pool) {
                kmem_cache_destroy(_trace_cache);
                return -ENOMEM;
        }

	return 0;
}

static void jobs_exit(void)
{
	BUG_ON(!list_empty(&_complete_jobs));
	BUG_ON(!list_empty(&_io_jobs));
	BUG_ON(!list_empty(&_pages_jobs));
        BUG_ON(!list_empty(&_trace_jobs));

        mempool_destroy(_trace_pool);
	mempool_destroy(_job_pool);
	kmem_cache_destroy(_job_cache);
        kmem_cache_destroy(_trace_cache);
	_job_pool = NULL;
	_job_cache = NULL;
        _trace_pool = NULL;
        _trace_cache = NULL;
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

	if (error) {
		/* TODO */
		DMERR("io_callback: io error");
		return;
	}

	DPRINTK("io_callback: %s block:%llu cache:%llu disk:%d",
		job->rw == READ ? "READ":"WRITE",
		job->cacheblock->block,
		job->cacheblock->cacheblock,
		job->cacheblock->disk);
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
	        bio->bi_sector, job->src.sector, job->dest.sector,
	        job->src.count, head, tail);

	if (bio_data_dir(bio) == READ) { /* The original request is a READ */
		if (0 == job->nr_pages) { /* The request is aligned to cache block */
			r = dm_io_async_bvec(1, &job->src, READ,
					bio->bi_io_vec + bio->bi_idx,
					io_callback, job);
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
	struct bio *bio = job->bio;
	struct cache_c *dmc = job->dmc;
	unsigned int offset, head, tail, remaining, nr_vecs;
	struct bio_vec *bvec;

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
	struct bio *bio;
	struct bio *n;

//	spin_lock(&cacheblock->lock);
	bio = bio_list_get(&bios);
	if (is_state(cacheblock->state, WRITEBACK)) { /* Write back finished */
		set_state(cacheblock->state, VALID);
	} else if (is_state(cacheblock->state, WRITETHROUGH)) { 
		set_state(cacheblock->state, INVALID);
	} else { /* Cache insertion finished */
		set_state(cacheblock->state, VALID);
		clear_state(cacheblock->state, RESERVED);
	}
//	spin_unlock(&cacheblock->lock);

	while (bio) {
		n = bio->bi_next;
		bio->bi_next = NULL;
		DPRINTK("Flush bio: %llu->%llu (%u bytes)",
		        cacheblock->block, bio->bi_sector, bio->bi_size);
		generic_make_request(bio);
		bio = n;
	}
}

static int do_complete(struct kcached_job *job)
{
	int r = 0;
	struct bio *bio = job->bio;
	
	DPRINTK("do_complete: %llu",bio->bi_sector);
	bio_endio(bio,bio->bi_size, 0);

	if (job->nr_pages > 0) {
		kfree(job->bvec);
		kcached_put_pages(job->dmc, job->pages);
	}

//	atomic_set(&job->cacheblock->status, 0);
	flush_bios(job->cacheblock);
	mempool_free(job, _job_pool);

	if (atomic_dec_and_test(&job->dmc->nr_jobs))
		wake_up(&job->dmc->destroyq);

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

static void do_work(void *ignored)
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

	r = dm_io_get(DMCACHE_COPY_PAGES);
	if (r) {
		DMERR("kcached_init: Could not resize dm io pool");
		free_bio_pages(dmc);
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

	dm_io_put(dmc->nr_pages);
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

static void copy_block(struct cache_c *dmc, struct io_region src,
	                   struct io_region dest, struct cacheblock *cacheblock)
{
	DPRINTK("Copying: %llu:%llu->%llu:%llu",
			src.sector, src.count * 512, dest.sector, dest.count * 512);
	kcopyd_copy(dmc->kcp_client, &src, 1, &dest, 0, \
			(kcopyd_notify_fn) copy_callback, (void *)cacheblock);
}

/*
static void write_back(struct cache_c *dmc,struct cacheblock *cache, unsigned int length)
{
	struct io_region src, dest;
	struct cacheblock *writecache;
	unsigned int i;

	src.bdev = dmc->cache_dev->bdev;
	src.sector = cache->cacheblock << dmc->block_shift;
	src.count = dmc->block_size * length;
	dest.bdev = virtual_mapping[cache->disk].src_dev->bdev;
	dest.sector = cache->block;
	dest.count = dmc->block_size * length;

	for (i=0; i<length; i++)
	{	
		writecache = radix_tree_lookup(dmc->cache, get_block_index((cache->block)+i,cache->disk));
		if(writecache != NULL){
			set_state(writecache->state, WRITEBACK);
		}
	}
	dmc->dirty_blocks -= length;
	copy_block(dmc, src, dest, cache); 
}*/

/****************************************************************************
 *  Functions for implementing the various cache operations.
 ****************************************************************************/
static sector_t get_block_index(sector_t block, int disk){
	return ( block + virtual_mapping[disk].dev_offset);
}

/*
 * Insert a block into the cache (in the frame specified by cache_block).
 */
static int cache_insert(struct cache_c *dmc, sector_t block,
	                    struct cacheblock *cache, int disk)
{
//	radix_tree_delete(dmc->cache, get_block_index(cache->block,disk));

	/* Mark the block as RESERVED because although it is allocated, the data are
       not in place until kcopyd finishes its job.
	 */
//	down(&dmc->lru_mutex);
//	list_move_tail(&cache->spot->list, dmc->lru);
//	up(&dmc->lru_mutex);

//	spin_lock(&cache->lock);
	set_state(cache->state, RESERVED);

	cache->disk = disk;
	cache->block = block;

	radix_tree_insert(dmc->cache, get_block_index(block,disk), (void *) cache);
//	spin_unlock(&cache->lock);

	return 1;
}

/*
 * Invalidate a block (specified by cache_block) in the cache.
 */
static void cache_invalidate(struct cache_c *dmc, struct cacheblock *cache)
{
	DPRINTK("Cache invalidate: Block %llu(%llu)",
                cache->cacheblock, cache->block);
	
//	spin_lock(&cache->lock);
	clear_state(cache->state, VALID);
	radix_tree_delete(dmc->cache, get_block_index(cache->block,cache->disk));
//	spin_unlock(&cache->lock);
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

	DPRINTK("HIT: cacheblock:%llu Block: %llu Disk:%d", cache->cacheblock, cache->block,cache->disk);

	dmc->cache_hits++;
        virtual_mapping[cache->disk].cache_hits++;

	if (bio_data_dir(bio) == READ) { /* READ hit */
		dmc->read_hits++;
                virtual_mapping[cache->disk].read_hits++;

		bio->bi_bdev = dmc->cache_dev->bdev;
		bio->bi_sector = (cache_block << dmc->block_shift)  + offset;

//		spin_lock(&cache->lock);

                if (is_state(cache->state, VALID)) { /* Valid cache block */
//			spin_unlock(&cache->lock);
			return 1;
		}

                /* Cache block is not ready yet */
                DPRINTK("Add to bio list %s(%llu)",
                                dmc->cache_dev->name, bio->bi_sector);
		bio_list_add(&bios, bio);

//		spin_unlock(&cache->lock);
		return 0;
	} else { /* WRITE hit */
		dmc->write_hits++;
                virtual_mapping[cache->disk].write_hits++;

		if (dmc->write_policy == WRITE_THROUGH) { /* Invalidate cached data */
			if (is_state(cache->state, VALID)) {
				cache_invalidate(dmc, cache);
				bio->bi_bdev = virtual_mapping[cache->disk].src_dev->bdev;
				return 1;
			}
				set_state(cache->state,WRITETHROUGH);
				bio_list_add(&bios, bio);
				return 0;
		}

		/* Write delay */
		if (!is_state(cache->state, DIRTY)) {
			set_state(cache->state, DIRTY);
			dmc->dirty_blocks++;
		}

//		spin_lock(&cache->lock);

 		/* In the middle of write back */
		if (is_state(cache->state, WRITEBACK)) {
			/* Delay this write until the block is written back */
			bio->bi_bdev = virtual_mapping[cache->disk].src_dev->bdev;
			DPRINTK("Add to bio list %s(%llu)",
					virtual_mapping[cache->disk].src_dev->name,
					(long long unsigned int)bio->bi_sector);
			bio_list_add(&bios, bio);
//			spin_unlock(&cache->lock);
			return 0;
		}

		/* Cache block not ready yet */
		if (is_state(cache->state, RESERVED)) {
			bio->bi_bdev = dmc->cache_dev->bdev;
			bio->bi_sector = (cache_block << dmc->block_shift) + offset;
			DPRINTK("Add to bio list %s(%llu)",
                                        dmc->cache_dev->name, bio->bi_sector);
			bio_list_add(&bios, bio);
//			spin_unlock(&cache->lock);
			return 0;
		}

		/* Serve the request from cache */
		bio->bi_bdev = dmc->cache_dev->bdev;
		bio->bi_sector = (cache_block << dmc->block_shift) + offset;

//		spin_unlock(&cache->lock);
		return 1;
	}
}

static struct kcached_job *new_kcached_job(struct cache_c *dmc, struct bio* bio,
	                                       sector_t request_block,
                                           struct cacheblock *cache)
{
	struct io_region src, dest;
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

	return job;
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

	down(&dmc->lru_mutex);
	cache = list_first_entry(dmc->lru, struct cacheblock, list);
	list_move_tail(&cache->list, dmc->lru);
	up(&dmc->lru_mutex);

        if(is_state(cache->state, RESERVED)) {
                DPRINTK("Got a spot RESERVED cacheblock: %llu val:%d ",
                                cache->cacheblock,cache->state);
                DPRINTK("Add to bio list %s(%llu)",
                                dmc->cache_dev->name, bio->bi_sector);
                bio_list_add(&bios, bio);
                return 0;
        }

	if (is_state(cache->state, VALID)) {
                DPRINTK("Replacing Block:%llu Cache Block: %llu To:%llu Disk:%d state:%d",
                        cache->block, cache->cacheblock, request_block,cache->disk,cache->state);
		dmc->replace++;
	} else {
		DPRINTK("Insert block: %llu at empty frame: %llu",
				request_block, cache->cacheblock);
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
                bio->bi_sector, job->nr_pages);

/*	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);

		if (!atomic_read(&cache->status))
			break;
		DPRINTK("WAIT for %llu - %llu ",
				(long long unsigned int)cache->cacheblock,
				(long long unsigned int)request_block);
		schedule();
	}
	atomic_set(&cache->status,1);
	set_current_state(TASK_RUNNING);
*/
	queue_job(job);

	return 0;
}

/*
 * Handle a write cache miss:
 *  If write-through, forward the request to source device.
 *  If write-back, update the metadata; fetch the necessary block from source
 *  device; write to cache device.
 */
static int cache_write_miss(struct cache_c *dmc, struct bio* bio, int disk) {
	struct cacheblock *cache ;

	unsigned int offset, head, tail;
	struct kcached_job *job;
	sector_t request_block, left;

	if (dmc->write_policy == WRITE_THROUGH) { /* Forward request to souuce */
		bio->bi_bdev = virtual_mapping[disk].src_dev->bdev;
		return 1;
	}

	down(&dmc->lru_mutex);
	cache = list_first_entry(dmc->lru, struct cacheblock, list);
	list_move_tail(&cache->list, dmc->lru);
	up(&dmc->lru_mutex);

	offset = (unsigned int)(bio->bi_sector & dmc->block_mask);
	request_block = bio->bi_sector - offset;

	if (is_state(cache->state,VALID)) {
		DPRINTK("Replacing Block:%llu to:%llu disk: %d",
		        cache->block, request_block,cache->disk);
		dmc->replace++;
	} else DPRINTK("Insert block %llu at empty frame %llu",
		request_block, cache->cacheblock);

	/* Write delay */
	cache_insert(dmc, request_block, cache,disk); /* Update metadata first */
	set_state(cache->state, DIRTY);
	dmc->dirty_blocks++;

	job = new_kcached_job(dmc, bio, request_block, cache);

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
                return cache_write_miss(dmc, bio, disk);
        }
}

static int virtual_cache_map(struct bio *bio){
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
	struct v_map *map_dev;

	sector_t request_block, offset;
	int res=0;
	int disk;

	offset = bio->bi_sector & dmc->block_mask;
	request_block = bio->bi_sector - offset;

	disk = virtual_cache_map(bio);
	map_dev = &virtual_mapping[disk];

	DPRINTK("Got a %s for %llu disk: %d ((%llu:%llu), %u bytes)",
			bio_rw(bio) == WRITE ? "WRITE" : (bio_rw(bio) == READ ?
				"READ":"READA"), bio->bi_sector, disk,request_block, offset,
			bio->bi_size);
/*   TRACING   */
	if(map_dev->trace){
		push_trace(bio->bi_sector, bio->bi_rw,bio->bi_size, map_dev->trace);
	}

	if (bio_data_dir(bio) == READ){
		dmc->reads++;
		virtual_mapping[disk].reads++;
	}else{
		dmc->writes++;
		virtual_mapping[disk].writes++;
	}

	if(is_state(virtual_mapping[disk].state,ENABLED)){

		cache = radix_tree_lookup(dmc->cache, get_block_index(request_block,disk));
		DPRINTK("Lookup for %llu (v_disk:%d index:%llu)",request_block,disk,get_block_index(request_block,disk));

		if(cache != NULL){
			if (is_state(cache->state, VALID) || is_state(cache->state, RESERVED)) {
//				if (cache->block == request_block && cache->disk == disk) 
				if (cache->disk == disk) 
					res = 1;
			}else{
				res = -1;			
				DPRINTK("cache(%llu:%llu) state %d-%s",cache->block,cache->cacheblock,cache->state,
					(cache->state == 0 ? "INVALID": 
					(cache->state == 1 ? "VALID": 
					(cache->state == 2 ? "RESERVED":
					(cache->state == 4 ? "DIRTY": 
					(cache->state == 8 ? "WRITEBACK":
					(cache->state == 16 ? "WRITETHROUGH":"")))))));
			}
		}
		if (-1 == res)
			DPRINTK("Cache lookup: Block Invalid %llu", request_block);
		else 
			DPRINTK("Cache lookup: Block %llu:%llu(%s)", request_block,res == 1 ? cache->cacheblock:res, 
					1 == res ? "HIT" : "MISS");

		if (1 == res){  // Cache hit; server request from cache 
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
        virtual_mapping[idx_mapping].writes = 0;
        virtual_mapping[idx_mapping].cache_hits = 0;
        virtual_mapping[idx_mapping].read_hits = 0;
        virtual_mapping[idx_mapping].write_hits = 0;
        virtual_mapping[idx_mapping].misses = 0;
        virtual_mapping[idx_mapping].read_misses = 0;
        virtual_mapping[idx_mapping].write_misses = 0;

	return 0;
}

/*
 * Convert a device path to a dev_t.
 */
static int lookup_device(const char *path, dev_t *dev)
{
	int r;
	struct nameidata nd;
	struct inode *inode;

	if ((r = path_lookup(path, LOOKUP_FOLLOW, &nd)))
		return r;
	inode = nd.dentry->d_inode;
	if (!inode) {
		r = -ENOENT;
		goto out;
	}

	if (!S_ISBLK(inode->i_mode)) {
		r = -ENOTBLK;
		goto out;
	}

	*dev = inode->i_rdev;

out:
	path_release(&nd);
	return r;
}

static int get_vm_index(char *vm_identifier){
	int i;
	DPRINTK("VM_name %s",vm_identifier);

	for (i=0; i < ctn_dm_dev ; i ++){
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
	sector_t i, order;
	sector_t data_size,dev_size;
	unsigned long long cache_size;
	int r = -EINVAL;
	struct mapped_device *mapped_dev;
	struct dm_dev_internal *dd;
	int idx_mapping = -1;
	unsigned int major,minor;
	struct sysinfo sys_info;

	dev_t dev = -1;

	if (argc < 2) {
		ti->error = "dm-cache: Need at least 2 arguments (src dev and cache dev)";
		goto bad;
	}

	/* This is the first time a mapping is created */
	if(init_flag == 0){
		virtual_mapping = kmalloc(sizeof(*virtual_mapping)*MAX_SRC_DEVICES , GFP_KERNEL);
		if (virtual_mapping == NULL){
			ti->error = "dm-cache: Failed to allocate cache context";
			r = -ENOMEM;
			goto bad;
		}
		shared_cache = kmalloc(sizeof(*shared_cache), GFP_KERNEL);
	}

	dmc = shared_cache;
	if (dmc == NULL) {
		ti->error = "dm-cache: Failed to allocate cache context";
		r = -ENOMEM;
		goto bad1;
	}

	/* Get the index for this VM */
	if(argc >= 8) {
		idx_mapping = get_vm_index(argv[7]);
		virtual_mapping[idx_mapping].identifier = idx_mapping;
		if(idx_mapping >= 0)
			strcpy(virtual_mapping[idx_mapping].vm_id,argv[7]);
		else{
			ti->error = "dm-cache: Virtual Machine identifier already exits";
			r = -EINVAL;
			goto bad2;
		}	
		virtual_mapping[idx_mapping].trace = NULL;
		if( argc >= 9 ) {

			virtual_mapping[idx_mapping].trace = kmalloc(sizeof(*virtual_mapping[idx_mapping].trace), GFP_KERNEL);
			if (virtual_mapping[idx_mapping].trace == NULL) {
				ti->error = "dm-trace: Cannot allocate linear context";
				r = -ENOMEM;
				goto bad1;
			}

			if (dm_get_device(ti, argv[8], 0, 0,
						dm_table_get_mode(ti->table), &virtual_mapping[idx_mapping].trace->trace_dev)) {
				ti->error = "dm-trace: trace device lookup failed";
				r = -EINVAL;
				goto bad1;
			}

			virtual_mapping[idx_mapping].trace->trace_pos = 0;
			virtual_mapping[idx_mapping].trace->trace_sector = 0;
			virtual_mapping[idx_mapping].trace->write_buf = vmalloc( MAX_SECTORS  * 512  + (512));
			if(!virtual_mapping[idx_mapping].trace->write_buf)
			{
				ti->error = "Failed to allocate memory for write buffer\n";
				goto bad1a;
			}

			memset(virtual_mapping[idx_mapping].trace->write_buf, 0, sizeof(virtual_mapping[idx_mapping].trace->write_buf));
		}	
	}else{
		ti->error = "dm-cache: Requires Virtual Machine identifier";
		r = -EINVAL;
		goto bad2;
	}

	/*  Adding source device */
	r = dm_get_device(ti, argv[0],0,ti->len,
			dm_table_get_mode(ti->table), &virtual_mapping[idx_mapping].src_dev);
	virtual_mapping[idx_mapping].ti = ti;
	if (r) {
		ti->error = "dm-cache: Source device lookup failed";
		goto bad2;
	} 
	DPRINTK("Registering source device %s:%llu",virtual_mapping[idx_mapping].src_dev->name,
			(long long unsigned int)virtual_mapping[idx_mapping].src_dev->bdev->bd_dev);
	

	/* Adding virtual cache devices */
	mapped_dev = dm_table_get_md(ti->table);
	if(sscanf(dm_device_name(mapped_dev),"%u:%u",&major,&minor)==2){
		virtual_mapping[idx_mapping].vcache_dev = MKDEV(major,minor);		
		DPRINTK("Registering virtual cache %d device %s------%llu",
				idx_mapping,
				dm_device_name(mapped_dev),
				(long long unsigned int)virtual_mapping[idx_mapping].vcache_dev);
	}
	dm_put(mapped_dev);

	/* Populate virtual machine mapping configuration */
	if(is_state(virtual_mapping[idx_mapping].state, EMPTY))
		populate_vm_mapping(idx_mapping,ti->len);
	put_state(virtual_mapping[idx_mapping].state, ENABLED);

	/* Adding global cache device */
	if(init_flag != 0) {
		DMINFO("Add new entry :%d (%s) (%luB per) mem for %llu-entry cache " \
				" block size:%u sectors(%uKB), %s)",
				idx_mapping,virtual_mapping[idx_mapping].vm_id,
				(unsigned long) sizeof(struct cacheblock),
				(unsigned long long) dmc->size,
				dmc->block_size, dmc->block_size >> (10-SECTOR_SHIFT),
				dmc->write_policy ? "write-back" : "write-through");
		goto init_sc;
	}

	dd =  kmalloc(sizeof(*dd), GFP_KERNEL);
	dd->dm_dev.mode = dm_table_get_mode(ti->table);		

	r = lookup_device(argv[1],&dev);
	dd->dm_dev.bdev = open_by_devnum(dev,dd->dm_dev.mode);

	if (r){
		ti->error = "dm-cache: Cache device lookup failed";
		kfree(dd);
		goto bad3;
	}

	r = blkdev_get( dd->dm_dev.bdev , dd->dm_dev.mode, 0);
	if (r) {
		ti->error = "dm-cache: Cache device get failed";
		kfree(dd);
		goto bad3;
	}else{

		format_dev_t(dd->dm_dev.name, dd->dm_dev.bdev->bd_dev);
		atomic_set(&dd->count, 0);
		atomic_inc(&dd->count);

		dmc->cache_dev = &dd->dm_dev;

		DPRINTK("Registering global cache device %s:%llu",argv[1],
				(long long unsigned int)dmc->cache_dev->bdev->bd_dev);
	}

	r = kcopyd_client_create(DMCACHE_COPY_PAGES, &dmc->kcp_client);
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
		DPRINTK("Persistence mode is not enable with full assoc");
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
	} else {
		dmc->block_size = DEFAULT_BLOCK_SIZE;
	}
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;

	if (argc >= 5) {
		if (sscanf(argv[4], "%llu", &cache_size) != 1) {
			ti->error = "dm-cache: Invalid cache size";
			r = -EINVAL;
			goto bad6;
		}
		dmc->size = (sector_t) cache_size;
	} else {
		dmc->size = DEFAULT_CACHE_SIZE;
	}
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
	} else {
		dmc->assoc = DEFAULT_CACHE_ASSOC;
	}

	DMINFO("%lldMB", (dmc->cache_dev->bdev->bd_inode->i_size >>9) >> (20-SECTOR_SHIFT));
	dev_size = dmc->cache_dev->bdev->bd_inode->i_size >> 9;
	data_size = dmc->size * dmc->block_size;

	if ((data_size) > dev_size) {
		DMERR("Requested cache size exeeds the cache device's capacity" \
		      "(%llu>%llu)",(unsigned long long) data_size,
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
	} else {
		dmc->write_policy = DEFAULT_WRITE_POLICY;
	}

	order = dmc->size * sizeof(struct cacheblock) + 
		sizeof(*dmc->lru);

	// Check system information
	si_meminfo (&sys_info);
	printk("Free memory before: %lu needed:%llu\n",sys_info.freeram,(order>0 ? (order>>10)/4 : 0));

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

/*	dmc->temp = (struct block_list *) vmalloc(dmc->size * (sizeof(struct block_list)));
	if(dmc->temp == NULL) {
		ti->error = "Unable to allocate memory for block lists ";
		r = -ENOMEM;
		goto bad6;
	}*/

	dmc->blocks = (struct cacheblock *) vmalloc(dmc->size * (sizeof(struct cacheblock)));
	if(dmc->blocks == NULL) {
		ti->error = "Unable to allocate memory for dmc cache blocks";
		r = -ENOMEM;
		goto bad8;
	}

	setup_timer(&dmc->reboot_time, (void *)reboot_map, (unsigned long )NULL );


	DMINFO("Allocate %llukB (%luB per) mem for %llu-entry cache" \
	       "(capacity:%lluMB, associativity:%u, block size:%u " \
	       "sectors(%uKB), %s)",
	       (unsigned long long) order >> 10, (unsigned long) sizeof(struct cacheblock),
	       (unsigned long long) dmc->size,
	       (unsigned long long) data_size >> (20-SECTOR_SHIFT),
	       dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT),
	       dmc->write_policy ? "write-back" : "write-through");

	si_meminfo (&sys_info);
	printk("Free memory After : %lu\n",sys_info.freeram);

	bio_list_init(&bios);

        for (i=0; i < dmc->size; i++) {
		dmc->blocks[i].state = 0;
//		atomic_set(&dmc->blocks[i].status, 0);
//               spin_lock_init(&dmc->blocks[i].lock);
                dmc->blocks[i].cacheblock = i;
                dmc->blocks[i].disk = -1;
                list_add(&dmc->blocks[i].list, dmc->lru);
        }

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
	dmc->write_hits = 0;	

	dmc->sequential_reads = 0;
        dmc->sequential_writes = 0;

init_sc:
	ti->split_io = dmc->block_size;
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
	kcopyd_client_destroy(dmc->kcp_client);
bad4:
	blkdev_put(dd->dm_dev.bdev);
	kfree(dd);
bad3:
	dm_put_device(ti,virtual_mapping[idx_mapping].src_dev);
bad2:
	kfree(shared_cache);
bad1a:
        dm_put_device(ti, virtual_mapping[idx_mapping].trace->trace_dev);
bad1:
	kfree(virtual_mapping);
bad:
	return r;
}
/*
static void cache_flush(struct cache_c *dmc, int disk)
{
	struct cacheblock *pos;
	struct cacheblock *cache;
	struct list_head *temp;
	unsigned int j;

	DMINFO("Flush dirty blocks (%llu) ...", (unsigned long long) dmc->dirty_blocks);

	list_for_each(temp, dmc->lru) {
		cache = list_entry(temp, struct cacheblock, list);
		if(cache->disk == disk && is_state(cache->state, DIRTY)) {
			j =1;
			for (pos = list_entry((temp)->next, typeof(*pos), list );
					&pos->list != (dmc->lru) && is_state(pos->state, DIRTY) &&
					pos->block == (cache->block + (j * dmc->block_size));
					pos = list_entry(pos->list.next, typeof(*pos), list)) {
				j++;	
			}
			dmc->dirty +=j;
//			write_back(dmc,cache,j);
			temp = &pos->list;
		}
	}
}*/

static int flush_virtual_cache ( int disk )
{
	struct cacheblock *cache;
	struct list_head *temp;
	struct cache_c *dmc = shared_cache;

	DMINFO("Flushing virtual cache: %d",disk);

	list_for_each(temp, dmc->lru) {
		cache = list_entry(temp, struct cacheblock, list);
		if(cache->disk == disk && is_state(cache->state, VALID)) {
                        cache_invalidate(dmc, cache);
//                        atomic_set(&cache->status, 0);
                }
	}
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

/*	if (dmc->dirty_blocks > 0) { 
		DPRINTK("Cleaning dirty blocks!! %d",cnt_active_map);
		cache_flush(dmc,map_dev->identifier);
	}*/

	if(cnt_active_map == 1) {
		kcached_client_destroy(dmc);
		kcopyd_client_destroy(dmc->kcp_client);

		if (dmc->reads + dmc->writes > 0)
			DMINFO("stats: reads(%lu), writes(%lu), cache hits(%lu, 0.%lu)," \
					"replacement(%lu), replaced dirty blocks(%lu), " \
					"flushed dirty blocks(%lu)",
					dmc->reads, dmc->writes, dmc->cache_hits,
					dmc->cache_hits * 100 / (dmc->reads + dmc->writes),
					dmc->replace, dmc->writeback, dmc->dirty);

		if (map_dev->trace){
			dm_put_device(ti, map_dev->trace->trace_dev);
			kfree(map_dev->trace);
		}

		//vfree((void *)dmc->temp);
		del_timer(&dmc->reboot_time);
		vfree((void *)dmc->blocks);
		vfree((void *)dmc->lru);
		vfree((void *)dmc->cache);

		blkdev_put(dd->dm_dev.bdev);
		DPRINTK("put global cache to destroy: %d",cnt_active_map);

		put_state(map_dev->state,DISABLED);
		dm_put_device(map_dev->ti,map_dev->src_dev);
		DPRINTK("put source to destroy: %d",cnt_active_map);

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
	dm_put_device(map_dev->ti,map_dev->src_dev);
	cnt_active_map--;
}

static void reboot_map( unsigned long ptr )
{
	struct v_map *map_dev;
        struct cache_c *dmc = shared_cache;

	DPRINTK("Timer complete!!");
	map_dev = (struct v_map *) dmc->reboot_ti->private;

	DPRINTK("Too much wait for  %s",map_dev->vm_id);
	put_state(map_dev->state,DISABLED);
	flush_virtual_cache(map_dev->identifier);
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

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("stats: reads(%lu), writes(%lu), cache hits(%lu), " \
				"replacement(%lu), replaced dirty blocks(%lu),misses(%lu), " \
				"read_miss(%lu), write_miss(%lu), read_hit(%lu), write_hit(%lu)\n ",\
				dmc->reads, dmc->writes, dmc->cache_hits,
				dmc->replace, dmc->writeback,
				dmc->misses, dmc->read_misses, dmc->write_misses,
				dmc->read_hits, dmc->write_hits);
		DMEMIT("VM-Stats: VM-id(%s: %s), reads(%lu), writes(%lu), cache hits(%lu), cache miss(%lu) "\
				"read_miss(%lu), write_miss(%lu), read_hit(%lu), write_hit(%lu),", \
				map_dev->vm_id, map_dev->state == ENABLED ? "ENABLED" : "DISABLED",
				map_dev->reads, map_dev->writes, map_dev->cache_hits,
				map_dev->misses, map_dev->read_misses, map_dev->write_misses,
				map_dev->read_hits, map_dev->write_hits);
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

static int cache_message(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct v_map *map_dev = (struct v_map *) ti->private;
        struct cache_c *dmc = shared_cache;
	int ms_sec;

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
		del_timer(&dmc->reboot_time);
		DPRINTK ("ENABLING! %s,%d", map_dev->vm_id,map_dev->state);
		return 1;
	} else if (strcmp(argv[0], "reboot")==0) {	
		DPRINTK ("REBOOTING! %s,%d",map_dev->vm_id,map_dev->state);
		dmc->reboot_ti = ti;

		if ( argc == 2 )
			sscanf(argv[1],"%d",&ms_sec);
		else
			ms_sec=120000;
		mod_timer(&shared_cache->reboot_time, jiffies + msecs_to_jiffies(ms_sec));
		
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
	int r;

	r = jobs_init();
	if (r)
		return r;

	_kcached_wq = create_singlethread_workqueue("kcached");
	if (!_kcached_wq) {
		DMERR("failed to start kcached");
		return -ENOMEM;
	}
	INIT_WORK(&_kcached_work, do_work, NULL);

	trace_wq = create_singlethread_workqueue("tracewq");
	if (!trace_wq) {
		DMERR("failed to start tracewq");
		return -ENOMEM;
	}

	INIT_WORK(&trace_work, do_trace, NULL);

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
        destroy_workqueue(trace_wq);
}

module_init(dm_cache_init);
module_exit(dm_cache_exit);

MODULE_DESCRIPTION(DM_NAME " cache target");
MODULE_AUTHOR("Ming Zhao <mingzhao99th@gmail.com>");
MODULE_LICENSE("GPL");
