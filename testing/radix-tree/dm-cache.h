#ifndef _dmcache_H
#define _dmcache_H

#define DMC_DEBUG 0
#define DM_MSG_PREFIX "cache"
#define DMC_PREFIX "dm-cache: "

#if DMC_DEBUG
#define DPRINTK( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

/* Default cache parameters */
#define DEFAULT_CACHE_SIZE      65536
#define DEFAULT_CACHE_ASSOC     1024
#define DEFAULT_BLOCK_SIZE      8
#define CONSECUTIVE_BLOCKS      512

/* Write policy */
#define WRITE_THROUGH 0
#define WRITE_BACK 1
#define DEFAULT_WRITE_POLICY WRITE_THROUGH

/* Number of pages for I/O */
#define DMCACHE_COPY_PAGES 1024

/* States of a cache block */
#define INVALID         0
#define VALID           1       /* Valid */
#define RESERVED        2       /* Allocated but data not in place yet */
#define DIRTY           4       /* Locally modified */
#define WRITEBACK       8       /* In the process of write back */

#define is_state(x, y)          (x & y)
#define set_state(x, y)         (x |= y)
#define clear_state(x, y)       (x &= ~y)

struct cache_c {
        struct dm_dev *src_dev;         /* Source device */
        struct dm_dev *cache_dev;       /* Cache device */
        struct dm_kcopyd_client *kcp_client; /* Kcopyd client for writing back data */
        struct work_struct active_flush;
        struct timer_list flush_time;
	
	struct radix_tree_root *cache; 	/* Radix tree for cache blocks */
//      struct cacheblock *cache;       /* Hash table for cache blocks */
        sector_t size;                  /* Cache size */
        unsigned int bits;              /* Cache size in bits */
        unsigned int assoc;             /* Cache associativity */
        unsigned int block_size;        /* Cache block size */
        unsigned int block_shift;       /* Cache block size in bits */
        unsigned int block_mask;        /* Cache block mask */
        unsigned int consecutive_shift; /* Consecutive blocks size in bits */
        unsigned long counter;          /* Logical timestamp of last access */
        unsigned int write_policy;      /* Cache write policy */
        sector_t dirty_blocks;          /* Number of dirty blocks */

        spinlock_t lock;                /* Lock to protect page allocation/deallocation */
        struct page_list *pages;        /* Pages for I/O */
        unsigned int nr_pages;          /* Number of pages */
        unsigned int nr_free_pages;     /* Number of free pages */
        wait_queue_head_t destroyq;     /* Wait queue for I/O completion */
        atomic_t nr_jobs;               /* Number of I/O jobs */
        struct dm_io_client *io_client;   /* Client memory pool*/

        /* Stats */
        unsigned long reads;            /* Number of reads */
        unsigned long writes;           /* Number of writes */
        unsigned long cache_hits;       /* Number of cache hits */
        unsigned long replace;          /* Number of cache replacements */
        unsigned long writeback;        /* Number of replaced dirty blocks */
        unsigned long dirty;            /* Number of submitted dirty blocks */
        int flushed;
        int (*caching_algorithm)(struct cache_c *, sector_t, sector_t *);
        int shouldEnd;
	struct list_head *lru;
};

/* Cache block metadata structure */
struct cacheblock {
        spinlock_t lock;        /* Lock to protect operations on the bio list */
        sector_t block;         /* Sector number of the cached block */
	sector_t cache;
        unsigned short state;   /* State of a block */
        unsigned long counter;  /* Logical timestamp of the block's last access */
        struct bio_list bios;   /* List of pending bios */
	struct block_list *spot; 
};
//LRU linked list
struct block_list{
	struct cacheblock * block;
	struct list_head list;
};
/* Structure for a kcached job */
struct kcached_job {
        struct list_head list;
        struct cache_c *dmc;
        struct bio *bio;        /* Original bio */
        struct dm_io_region src;
        struct dm_io_region dest;
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

#endif
