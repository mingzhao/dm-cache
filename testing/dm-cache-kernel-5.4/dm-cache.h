#ifndef __DM_CACHE_H
#define __DM_CACHE_H

#include <asm/atomic.h>
#include <asm/checksum.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <linux/hrtimer.h>
#include <linux/device-mapper.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/dm-kcopyd.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include "dm.h"

/* Write policy */
#define WRITE_THROUGH 0
#define WRITE_BACK 1

/* Number of pages for I/O */
#define DMCACHE_COPY_PAGES 1024
#define DMC_SECTOR_SIZE 512

/* The supported algorithms*/
#define ALGO_NONE 0
#define ALGO_LRU 1
#define ALGO_ARC 2
#define ALGO_GLRU 3

/* States of a cache block */
#define INVALID   0
#define VALID   1 /* Valid */
#define RESERVED  2 /* Allocated but data not in place yet */
#define DIRTY   4 /* Locally modified */
#define WRITEBACK 8 /* In the process of write back */

#define MIN_JOBS 4096

#define ID_OFFSET 48

#define is_state(x, y)    (x & y)
#define set_state(x, y)   (x |= y)
#define clear_state(x, y) (x &= ~y)

#define jobstats(x)         &(job->dmc->stats).x
#define dmcstats(x)         &(dmc->stats).x
#define incstats(x)         atomic64_inc(x);
#define jobstats_inc(x)     atomic64_inc(&(job->dmc->stats).x);
#define dmcstats_inc(x)     atomic64_inc(&(dmc->stats).x);
#define jobstats_dec(x)     atomic64_dec(&(job->dmc->stats).x);
#define dmcstats_dec(x)     atomic64_dec(&(dmc->stats).x);
#define dmcstats_set(x,y)   atomic64_set(&(dmc->stats).x, (y));
#define bio2sec(x)          (x)->bi_iter.bi_sector

#define CACHE_UNKNOWN 0
#define CACHE_MISS 1
#define CACHE_HIT 2

struct rpl_result_c;

/* Structure for a dm-cache job */
struct dmc_job_c {
  struct dmc_c *dmc;
  uint64_t id;
  struct list_head list;
  struct bio *src_bio;
  struct bio *clone_bio;
  struct bio *cache_read_bio;
  struct dm_io_region src;
  struct dm_io_region cache;
  struct cache_meta_c *cache_node;
  uint64_t src_data_id;
  char *hash;
  int loc;
  int ori_rw;
  int rw;
  int disk;
  int dmc_case;
};

struct info {
  /* Normal stats*/
  atomic64_t total_reqs;
  atomic64_t total_reads;
  atomic64_t total_writes;
  atomic64_t cache_hits;
  atomic64_t cache_read_hits;
  atomic64_t cache_write_hits;
  atomic64_t cache_misses;
  atomic64_t cache_read_misses;
  atomic64_t cache_write_misses;
  atomic64_t ssd_reads;
  atomic64_t ssd_writes;
  atomic64_t disk_reads;
  atomic64_t disk_writes;
  atomic64_t resubmits;
  atomic64_t dirty_caches;
  atomic64_t cache_evict;
  atomic64_t free_cache_cnt;
  atomic64_t val_cache_cnt;
  atomic64_t tree_cnt;
};

/*
 * Cache context
 */
struct dmc_c {
  struct dm_dev *src_dev;     /* Source device */
  struct dm_dev *cache_dev;   /* Cache device */
  struct dm_kcopyd_client *kcp_client; /* Kcopyd client for writing back data */

  struct cache_meta_c *cache_meta_array; /* Array for cache blocks metadata*/
  struct cache_meta_c *home_meta_array;  /* Array for home metadata*/
  struct radix_tree_root cache_tree;

  uint64_t src_block_quantity;     /* Source device size */
  uint64_t cache_block_quantity;     /* Cache size */
  uint64_t cache_block_in_sector;    /* Cache block size */
  uint64_t block_shift;   /* Cache block size in bits */
  uint64_t block_mask;    /* Cache block mask */
  uint64_t consecutive_shift; /* Consecutive blocks size in bits */
  uint64_t counter;      /* Logical timestamp of last access */
  uint64_t write_policy;  /* Cache write policy */
  sector_t dirty_blocks;      /* Number of dirty blocks */

  spinlock_t lock;        /* Lock to protect page allocation/deallocation */
  struct page_list *pages;    /* Pages for I/O */
  uint64_t nr_pages;      /* Number of pages */
  uint64_t nr_free_pages; /* Number of free pages */
  wait_queue_head_t destroyq; /* Wait queue for I/O completion */
  atomic_t nr_jobs;       /* Number of I/O jobs */
  struct dm_io_client *io_client;   /* Client memory pool*/
  struct bio_set dmc_bio_set;
  mempool_t cache_metadata_pool;

  void *rpl_c;            /* The cache replacement algorithm context*/
  uint32_t replace_algo;
  int (*priotize_meta)(struct dmc_job_c *job,
                       struct rpl_result_c *rpl_result);
  uint64_t free_idx;

  struct info stats;
  uint64_t cmn_id;
  uint32_t cache_meta_size;
};

struct dmc_list_head_c {
  uint32_t id;
  struct dmc_c *dmc;
  struct list_head head;
  uint64_t size;
  spinlock_t lock;
};

/* Backend storage data structure*/
struct cache_meta_c {
  uint64_t cache_id;
  uint64_t data_id;       // 2 bytes cache node 6 bytes block ID
  uint16_t cache_state;
  struct list_head entry;       // Use for cache algorithm data structure
  struct dmc_list_head_c *rpl_head;  // Idenitity of data location
  spinlock_t lock;
};

struct rpl_result_c {
  struct cache_meta_c *evict_meta;
  uint64_t write_cache_id;
};

#define DMC_INFO(s, ...) pr_info("###[%s]###" s, __FUNCTION__, ##__VA_ARGS__)

#define DMC_ERR(s, ...) pr_err("###[%s]###" s, __FUNCTION__, ##__VA_ARGS__)

#define DMC_BIO(bio, s, ...) { \
  pr_debug("###[%s]###" s "BIO: bio_opf[0x%x] " \
          "bi_sector[%llu] bi_size[0x%x] bi_idx[%u] has_data[%s] " \
          "bio_data[0x%02x] " , \
          __FUNCTION__, __VA_ARGS__ ## bio->bi_opf, bio->bi_iter.bi_sector, \
          bio_sectors(bio), bio->bi_iter.bi_idx, \
          bio_has_data(bio) ? "Y" : "N", \
          ((uint8_t *)bio_data(bio))[0] ); \
}

#define DMC_INFO_JOB(job, s, ...) { \
  pr_debug("###[%s]###" s " rw[%c] node[%llu] blk[0x%llu] " \
          "bi_sector_size[0x%x] " , \
          __FUNCTION__, __VA_ARGS__ ## job->rw == READ ? 'R' : 'W', \
          job->src_data_id >> ID_OFFSET, \
          job->src_data_id & ~(0xffffULL << ID_OFFSET), \
          bio_sectors(job->src_bio)); \
}

#define DMC_INFO_CACHE(cache, s, ...) { \
  pr_debug("###[%s]###" s " cache_block[0x%llx] data_block[%llu] " \
          "list_id[%llu]" , \
          __FUNCTION__, __VA_ARGS__ ## cache->cache_id, cache->data_id, \
          cache->rpl_head != NULL ? cache->rpl_head->id : U64_MAX); \
}

#endif /* __DM_CACHE_H */
