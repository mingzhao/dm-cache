#include "dm-cache.h"
#include "lru.h"
#include "dm-container.h"

#define DM_MSG_PREFIX "gdcache"

static DEFINE_SPINLOCK(cache_tree_lock);
#define TREE_LOCK     spin_lock(&cache_tree_lock);
#define TREE_UNLOCK     spin_unlock(&cache_tree_lock);

static DEFINE_SPINLOCK(job_lock);
#define JOB_LIST_LOCK     spin_lock(&job_lock);
#define JOB_LIST_UNLOCK   spin_unlock(&job_lock);
static LIST_HEAD(io_jobs);

static LIST_HEAD(complete_jobs);

static LIST_HEAD(cache_read_jobs);

static DEFINE_SPINLOCK(meta_update_lock);
#define META_LOCK     spin_lock(&meta_update_lock);
#define META_UNLOCK     spin_unlock(&meta_update_lock);

DECLARE_DM_KCOPYD_THROTTLE_WITH_MODULE_PARM(clone_hydration_throttle,
                                            "A percentage of time allocated for hydrating regions");

static mempool_t job_pool;
static struct kmem_cache *job_cache;
static struct kmem_cache *metadata_cache;

static struct workqueue_struct *dmc_io_wq;
static struct work_struct dmc_io_work;

void debug_bio(struct bio *bio, char *string)
{
  struct bvec_iter iter;
  struct bio_vec bvec;
  int i = 0;

  DMC_INFO("[%s] BIO[%p] sector[0x%llx] has Data: %s",
           string, bio, bio->bi_iter.bi_sector,
           bio_has_data(bio) ? "YES" : "NO");

  bio_for_each_segment(bvec, bio, iter) {
    DMC_INFO("iter[%d] iter_length[%u]", i, bio_iter_len(bio, iter));
  }
}

uint64_t bio_to_data_id(struct bio *src_bio, struct dmc_c *dmc) {
  return (src_bio->bi_iter.bi_sector / dmc->cache_block_in_sector) |
    (dmc->cmn_id << ID_OFFSET);
}

uint64_t data_id_to_block_id(struct dmc_c *dmc, uint64_t data_id) {
  return (data_id & ~(0xffffUL << 48));
}

static int kcached_init(struct dmc_c *dmc)
{
  spin_lock_init(&dmc->lock);
  init_waitqueue_head(&dmc->destroyq);
  atomic_set(&dmc->nr_jobs, 0);
  return 0;
}

static inline void wake_job(void)
{
  queue_work(dmc_io_wq, &dmc_io_work);
}

static struct cache_meta_c *dmc_cache_lookup(struct dmc_c *dmc,
                                             uint64_t src_data_id)
{
  struct cache_meta_c *cache_node;
  TREE_LOCK;
  cache_node = radix_tree_lookup(&dmc->cache_tree, src_data_id);
  TREE_UNLOCK;
  return cache_node;
}

static int dmc_cache_insert(struct dmc_c *dmc, struct cache_meta_c *cache_node)
{
  int ret;
  BUG_ON(cache_node->cache_id == U64_MAX);
  TREE_LOCK;
  ret = radix_tree_insert(&dmc->cache_tree,
                          cache_node->data_id, (void *)cache_node);
  TREE_UNLOCK;
  return ret;
}

static struct cache_meta_c *dmc_cache_delete(struct dmc_c *dmc,
                                             struct cache_meta_c *cache_node)
{
  struct cache_meta_c *evict;
  TREE_LOCK;
  evict = radix_tree_delete(&dmc->cache_tree, cache_node->data_id);
  TREE_UNLOCK;
  return evict;
}

static struct dmc_job_c *create_cache_job(struct dmc_c *dmc, struct bio *bio)
{
  struct dm_io_region src, cache;
  struct dmc_job_c *job;

  src.bdev = dmc->src_dev->bdev;
  src.sector = bio->bi_iter.bi_sector;
  src.count = dmc->cache_block_in_sector;

  cache.bdev = dmc->cache_dev->bdev;
  cache.sector = -1;
  cache.count = src.count;

  job = mempool_alloc(&job_pool, GFP_NOIO);
  job->dmc = dmc;
  job->src_bio = bio;
  job->src = src;
  job->cache = cache;
  job->src_data_id = bio_to_data_id(bio, dmc);
  job->ori_rw = bio_data_dir(bio);
  job->rw = bio_data_dir(bio);

  dmcstats_inc(total_reqs);
  job->id = atomic64_read(&dmc->stats.total_reqs);

  return job;
}

/*
 * Functions to push and pop a job onto the head of a given job list.
 */
static inline struct dmc_job_c *pop_job(struct list_head *jobs)
{
  struct dmc_job_c *job = NULL;
  unsigned long flags;

  spin_lock_irqsave(&job_lock, flags);
  if (!list_empty(jobs)) {
    job = list_entry(jobs->next, struct dmc_job_c, list);
    list_del(&job->list);
  }
  spin_unlock_irqrestore(&job_lock, flags);

  return job;
}

static inline void push_job(struct list_head *jobs, struct dmc_job_c *job)
{
  unsigned long flags;
  spin_lock_irqsave(&job_lock, flags);
  list_add_tail(&job->list, jobs);
  spin_unlock_irqrestore(&job_lock, flags);
}

void dmc_read_miss_callback(struct bio *clone_bio)
{
  struct dmc_job_c *job = (struct dmc_job_c *)clone_bio->bi_private;
  push_job(&cache_read_jobs, job);
  wake_job();
}

void dmc_wb_callback(int read_err, unsigned int write_err, void *context)
{
  DMC_INFO("========Flush data back success!!!");
}

void dmc_flush_src(struct dmc_job_c *job, struct rpl_result_c *res)
{
  struct dm_io_region src, dest;
  struct dmc_c *dmc = job->dmc;
  uint64_t dest_blk_id;

  src.bdev = dmc->cache_dev->bdev;
  src.sector = res->evict_meta->cache_id * dmc->cache_block_in_sector;
  src.count = dmc->cache_block_in_sector;

  dest_blk_id = data_id_to_block_id(dmc, res->evict_meta->data_id);

  dest.bdev = dmc->src_dev->bdev;
  dest.sector = dest_blk_id << dmc->block_shift;
  dest.count = dmc->cache_block_in_sector;

  dmcstats_inc(cache_evict);
  dm_kcopyd_copy(dmc->kcp_client, &src, 1, &dest, 0,
                 (dm_kcopyd_notify_fn)dmc_wb_callback, res->evict_meta);
}

int dmc_local_read(struct dmc_job_c *job)
{
  struct cache_meta_c *cache_node = NULL;
  struct rpl_result_c res;
  struct dmc_c *dmc = job->dmc;
  int write_res;
  BUG_ON(job->src_bio == NULL);

  META_LOCK;
  cache_node = dmc_cache_lookup(job->dmc, job->src_data_id);
  if (cache_node != NULL) {
    write_res = CACHE_HIT;
    DMC_INFO_JOB(job, " |CACHE_READ_HIT| ");
    job->cache_node = cache_node;
    job->dmc->priotize_meta(job, &res);
    bio_set_dev(job->src_bio, job->dmc->cache_dev->bdev);
    job->src_bio->bi_iter.bi_sector =
      cache_node->cache_id * job->dmc->cache_block_in_sector;
    dmcstats_inc(cache_read_hits);
    dmcstats_inc(cache_hits);
    dmcstats_inc(ssd_reads);
    generic_make_request(job->src_bio);
  } else {
    DMC_INFO_JOB(job, " |CACHE_READ_MISS| ");
    write_res = CACHE_MISS;
    bio_set_dev(job->src_bio, job->dmc->src_dev->bdev);

    // Preallocate the cache block for the data.
    res.write_cache_id = U64_MAX;
    res.evict_meta = NULL;
    job->cache_node = NULL;
    job->dmc->priotize_meta(job, &res);
    BUG_ON(job->cache_node == NULL);
    dmc_cache_insert(job->dmc, job->cache_node);
    // evict_meta and write_cache_id update in the replacement algorithm.
    // Only return what should be moved from the Metadata tree.
    if (res.evict_meta != NULL) {
      BUG_ON(res.write_cache_id == U64_MAX);
      DMC_INFO_JOB(job, " | Delete from the tree | ");
      dmc_cache_delete(job->dmc, res.evict_meta);
      dmc_flush_src(job, &res);
      mempool_free(res.evict_meta, &job->dmc->cache_metadata_pool);
    }

    // Clone BIO and fetch data from source deivce
    job->clone_bio = bio_clone_fast(job->src_bio, GFP_NOIO,
                                    &job->dmc->dmc_bio_set);
    BUG_ON(job->clone_bio == NULL);
    job->clone_bio->bi_end_io = dmc_read_miss_callback;
    job->clone_bio->bi_private = job;

    DMC_BIO(job->clone_bio, "reading source device");
    dmcstats_inc(cache_read_misses);
    dmcstats_inc(cache_misses);
    dmcstats_inc(disk_reads);
    generic_make_request(job->clone_bio);
  }

  META_UNLOCK;

  return 0;
}

int dmc_cache_data(struct dmc_job_c *job)
{
  struct cache_meta_c *cache_node = NULL;
  int write_res = CACHE_HIT;
  struct rpl_result_c res;
  struct dmc_c *dmc = job->dmc;
  int need_insert_tree = 0;

  BUG_ON(job->src_bio == NULL);

  META_LOCK;
  cache_node = dmc_cache_lookup(job->dmc, job->src_data_id);
  if (cache_node != NULL) {
    DMC_INFO_JOB(job, " |CACHE_UPDATE| ");
    dmcstats_inc(cache_write_hits);
  } else {
    DMC_INFO_JOB(job, " |CACHE_NEW_DATA| ");
    write_res = CACHE_MISS;
    BUG_ON(data_id_to_block_id(job->dmc, job->src_data_id) >=
           job->dmc->src_block_quantity);
    need_insert_tree = 1;
    dmcstats_inc(cache_write_misses);
  }

  res.write_cache_id = U64_MAX;
  res.evict_meta = NULL;

  job->cache_node = cache_node;
  job->dmc->priotize_meta(job, &res);
  BUG_ON(job->cache_node == NULL);

  if (need_insert_tree) {
    dmc_cache_insert(job->dmc, job->cache_node);
  }

  // evict_meta and write_cache_id update in the replacement algorithm.
  // Only return what should be moved from the Metadata tree.
  if (res.evict_meta != NULL) {
    BUG_ON(res.write_cache_id == U64_MAX);
    DMC_INFO_JOB(job, " | Delete from the tree | ");
    dmc_cache_delete(job->dmc, res.evict_meta);
    dmc_flush_src(job, &res);
    mempool_free(res.evict_meta, &job->dmc->cache_metadata_pool);
  }
  META_UNLOCK;

  // Writes new data to cache device.
  BUG_ON(res.write_cache_id == U64_MAX);
  job->src_bio->bi_iter.bi_sector = res.write_cache_id *
    job->dmc->cache_block_in_sector;
  bio_set_dev(job->src_bio, job->dmc->cache_dev->bdev);
  DMC_INFO(" write_cache_id[%llu], cache_loc_sector[%llx]",
           res.write_cache_id,
           data_id_to_block_id(job->dmc, res.write_cache_id));
  dmcstats_inc(ssd_writes);
  generic_make_request(job->src_bio);
  return write_res;
}

int dmc_local_write(struct dmc_job_c *job)
{
  dmc_cache_data(job);
  mempool_free(job, &job_pool);
  return 0;
}

static int io_entry_func(struct dmc_job_c *job)
{
  int r = 0;

  DMC_INFO_JOB(job, " | Process job |--->");

  // No matter global managed or distributed managed, metadata exists means
  // cache hit. But meatadata does not exists not mean it is miss in global.
  r = (job->rw == READ) ? dmc_local_read(job) : dmc_local_write(job);

  return r;
}

/*
 * Run through a list for as long as possible.  Returns the count
 * of successful jobs.
 */
static int process_jobs(struct list_head *jobs_list,
                        int (*fn)(struct dmc_job_c *), char *name)
{
  struct dmc_job_c *job;
  int r, success_count = 0;
  while ((job = pop_job(jobs_list))) {
    // If the job success, return 0. r < 0 means error, r > 0 mean retry.
    r = fn(job);
    if (r < 0) {
      DMC_ERR("process_jobs: Job processing error");
    } else if (r > 0) {
      // Job is not able to process, requeue back to the list.
      DMC_ERR("process_jobs error(%s)\n", name);
      push_job(jobs_list, job);
      break;
    }
    success_count++;
  }
  return success_count;
}

static int do_complete(struct dmc_job_c *job)
{
  bio_endio(job->src_bio);
  bio_put(job->clone_bio);
  mempool_free(job, &job_pool);

  return 0;
}

void cache_read_callback(struct bio *clone_bio)
{
  struct dmc_job_c *job = (struct dmc_job_c *)clone_bio->bi_private;
  job->cache_node->cache_state = VALID;
  push_job(&complete_jobs, job);
  wake_job();
}

static int do_cache_read(struct dmc_job_c *job)
{
  struct bio *clone_bio;
  struct dmc_c *dmc = job->dmc;
  // Clone bio and send out the data to cache device
  // In the end, end the original i/o.
  // Cannot use the orignal I/O since callback is different.
  clone_bio = bio_clone_fast(job->src_bio, GFP_NOIO, &job->dmc->dmc_bio_set);
  job->clone_bio = clone_bio;
  BUG_ON(clone_bio == NULL);
  clone_bio->bi_end_io = cache_read_callback;
  clone_bio->bi_private = job;
  clone_bio->bi_iter.bi_sector = job->cache_node->cache_id *
    job->dmc->cache_block_in_sector;
  clone_bio->bi_opf = (clone_bio->bi_opf & ~(bio_data_dir(clone_bio))) |  WRITE;

  DMC_INFO_JOB(job, "Got data,  ready write to cache");
  bio_set_dev(clone_bio, job->dmc->cache_dev->bdev);
  dmcstats_inc(ssd_writes);
  generic_make_request(clone_bio);
  return 0;
}

static void do_io_work_func(struct work_struct *ignored)
{
  process_jobs(&complete_jobs, do_complete, "do_complete");
  process_jobs(&cache_read_jobs, do_cache_read, "do_cache_read");
  process_jobs(&io_jobs, io_entry_func, "io_entry");
}

/*
 * Decide the mapping and perform necessary cache operations for a bio request.
 */
static int cache_map(struct dm_target *ti, struct bio *bio)
{
  struct dmc_c *dmc = (struct dmc_c *) ti->private;
  sector_t offset;
  struct dmc_job_c *job;

  if (bio->bi_iter.bi_sector >
      dmc->src_block_quantity * dmc->cache_block_in_sector) {
    bio_set_dev(bio, dmc->src_dev->bdev);
    generic_make_request(bio);
    goto bio_end;
  }

  offset = bio->bi_iter.bi_sector & dmc->block_mask;
  BUG_ON(offset != 0);

  /* If cannot create the job, forward the request to source device*/
  /* Notice: If bio is read, bio will be cloned anyway */
  job = create_cache_job(dmc, bio);

  DMC_INFO_JOB(job, "|||======||CreateJOB||======|||");
  DMC_BIO(bio,      "|||------||New   BIO||------|||");

  if (bio_data_dir(bio) == READ) {
    dmcstats_inc(total_reads);
  } else {
    dmcstats_inc(total_writes);
  }

  atomic_inc(&job->dmc->nr_jobs);
  push_job(&io_jobs, job);
  wake_job();

bio_end:
  return DM_MAPIO_SUBMITTED;
}

/*
 * Construct a cache mapping.
 *  arg[0]: path to source device
 *  arg[1]: path to cache device
 *  arg[2]: cache block size (in sectors)
 *  arg[3]: cache size (in blocks)
 *  arg[4]: cache replacement algorithm
 *  arg[5]: write caching policy
 *  arg[6]: cache map node ID
 */
static int cache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
  struct dmc_c *dmc;
  int r = -EINVAL;
  uint64_t cache_dev_size_bytes, allocated_cache_size_bytes;
  uint64_t src_dev_size_bytes;

  if (argc < 5) {
    ti->error = "dm-cache: Need at least 5 arguments (src dev and cache dev)";
    goto bad;
  }

  dmc = kzalloc(sizeof(*dmc), GFP_KERNEL);
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
  }
  src_dev_size_bytes = dmc->src_dev->bdev->bd_inode->i_size;

  r = dm_get_device(ti, argv[1],
                    dm_table_get_mode(ti->table), &dmc->cache_dev);
  if (r) {
    ti->error = "dm-cache: Cache device lookup failed";
    goto bad2;
  }
  cache_dev_size_bytes = dmc->cache_dev->bdev->bd_inode->i_size;

  DMC_INFO("cache_dev_size=%lld GiB, "
           "src_dev_size=%lld GiB, "
           "cache max address: 0x%llx, "
           "src max address: 0x%llx",
           cache_dev_size_bytes / ( 1024 * 1024 *1024),
           src_dev_size_bytes / (1024 * 1024 * 1024),
           cache_dev_size_bytes, src_dev_size_bytes);

  dmc->io_client = dm_io_client_create();
  if (IS_ERR(dmc->io_client)) {
    r = PTR_ERR(dmc->io_client);
    ti->error = "Failed to create io client\n";
    goto bad3;
  }

  dmc->kcp_client = dm_kcopyd_client_create(&dm_kcopyd_throttle);
  if (IS_ERR(dmc->kcp_client)) {
    ti->error = "Failed to initialize kcopyd client";
    goto bad4;
  }

  r = kcached_init(dmc);
  if (r) {
    ti->error = "Failed to initialize kcached";
    goto bad5;
  }

  if (sscanf(argv[2], "%llu", &dmc->cache_block_in_sector) != 1) {
    ti->error = "dm-cache: Invalid block size";
    r = -EINVAL;
    goto bad5;
  }

  if (!dmc->cache_block_in_sector || (dmc->cache_block_in_sector &
                                      (dmc->cache_block_in_sector - 1))) {
    ti->error = "dm-cache: Invalid block size";
    r = -EINVAL;
    goto bad5;
  }

  dmc->block_shift = ffs(dmc->cache_block_in_sector) - 1;
  dmc->block_mask = dmc->cache_block_in_sector - 1;

  if (sscanf(argv[3], "%llu", &dmc->cache_block_quantity) != 1) {
    ti->error = "dm-cache: Invalid cache size";
    r = -EINVAL;
    goto bad5;
  }

  if (sscanf(argv[4], "%u", &dmc->replace_algo) != 1) {
    ti->error = "dm-cache: Invalid replacement algorithm";
    r = -EINVAL;
    goto bad5;
  }

  allocated_cache_size_bytes =
    dmc->cache_block_quantity * dmc->cache_block_in_sector * DMC_SECTOR_SIZE;
  if (allocated_cache_size_bytes > cache_dev_size_bytes) {
    DMC_ERR("Requested cache size (%llu) bytes exeeds device capacity (%llu)",
            cache_dev_size_bytes, allocated_cache_size_bytes);
    ti->error = "dm-cache: Invalid cache size";
    r = -EINVAL;
    goto bad5;
  }

  if (sscanf(argv[5], "%llu", &dmc->write_policy) != 1) {
    ti->error = "dm-cache: Invalid cache write policy";
    r = -EINVAL;
    goto bad5;
  }

  if (sscanf(argv[6], "%llu", &dmc->cmn_id) != 1) {
    ti->error = "dm-cache: Invalid cahce map node ID";
    r = -EINVAL;
    goto bad5;
  }

  if (dmc->write_policy != WRITE_THROUGH && dmc->write_policy != WRITE_BACK) {
    ti->error = "dm-cache: Invalid cache write policy";
    r = -EINVAL;
    goto bad5;
  }

  r = bioset_init(&dmc->dmc_bio_set, BIO_POOL_SIZE, 0, 0);
  if (r) {
    ti->error = "Failed to create bio_set";
    goto bad6;
  }

  DMC_INFO("Allocated 0x%llx/0x%llx cache size from device %s for source_dev %s",
           allocated_cache_size_bytes, cache_dev_size_bytes, argv[0], argv[1]);
  DMC_INFO("Cache_block_size_in_sector[%llu], cache policy %s",
           dmc->cache_block_in_sector, dmc->write_policy ?
           "write-back" : "write-through");

  metadata_cache = KMEM_CACHE(cache_meta_c, 0);
  if (!metadata_cache) return -ENOMEM;

  r = mempool_init_slab_pool(&dmc->cache_metadata_pool,
                             dmc->cache_meta_size, metadata_cache);
  if (r) {
    pr_err("Error: Failed to create job pool!");
  }

  // -----------------------------------------------------------
  // Cache meta array size is twice of the cache block quantity.
  // Preallocate in array may not work in distributed env
  //dmc->cache_meta_size = dmc->cache_block_quantity * 2;
  //dmc->cache_meta_array = vmalloc(dmc->cache_meta_size *
  //                                sizeof(struct cache_meta_c));
  //if (!dmc->cache_meta_array) {
  //  ti->error = "Unable to allocate memory";
  //  r = -ENOMEM;
  //  goto bad5;
  //}
  //dmc->home_meta_array = vmalloc(dmc->cache_meta_size *
  //                               sizeof(struct cache_meta_c));
  //if (!dmc->home_meta_array) {
  //  ti->error = "Unable to allocate memory";
  //  r = -ENOMEM;
  //  goto bad5;
  //}

  //for (i = 0; i < dmc->cache_meta_size; i++) {
  //  spin_lock_init(&dmc->cache_meta_array[i].lock);
  //}
  //-----------------------------------------------------------

  dmc->src_block_quantity = src_dev_size_bytes /
    (dmc->cache_block_in_sector * DMC_SECTOR_SIZE);
  DMC_INFO("source_block_quantity = %lld ", dmc->src_block_quantity);
  DMC_INFO("cache_block_quantity = %lld ", dmc->cache_block_quantity);

  INIT_RADIX_TREE(&dmc->cache_tree, GFP_NOIO);
  dmc->free_idx = 0;

  switch(dmc->replace_algo) {
  case ALGO_LRU:
    DMC_INFO("===============LRU Initializing===============");
    r = lru_init(dmc);
    dmc->priotize_meta = lru_priotize_meta;
    break;
  default:
    DMC_INFO("=======Unknown Algotihm [%d]========", dmc->replace_algo);
  }

  ti->private = dmc;
  return 0;
bad6:
  bioset_exit(&dmc->dmc_bio_set);
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

/*
 *  Output cache stats upon request of device status;
 */
static void cache_status(struct dm_target *ti, status_type_t type,
                         unsigned status_flags, char *result, unsigned maxlen)
{
  struct dmc_c *dmc = (struct dmc_c *) ti->private;
  int sz = 0;
  switch (type) {
  case STATUSTYPE_INFO:
    DMEMIT("============Statistics===========\n");
    DMEMIT("total_reqs[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.total_reqs));
    DMEMIT("total_reads[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.total_reads));
    DMEMIT("total_writes[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.total_writes));
    DMEMIT("cache_hits[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.cache_hits));
    DMEMIT("cache_read_hits[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.cache_read_hits));
    DMEMIT("cache_write_hits[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.cache_write_hits));
    DMEMIT("cache_misses[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.cache_misses));
    DMEMIT("cache_read_misses[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.cache_read_misses));
    DMEMIT("cache_write_misses[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.cache_write_misses));
    DMEMIT("ssd_reads[%llu]\n", (uint64_t)atomic64_read(&dmc->stats.ssd_reads));
    DMEMIT("ssd_writes[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.ssd_writes));
    DMEMIT("disk_reads[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.disk_reads));
    DMEMIT("disk_writes[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.disk_writes));
    DMEMIT("resubmits[%llu]\n", (uint64_t)atomic64_read(&dmc->stats.resubmits));
    DMEMIT("dirty_caches[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.dirty_caches));
    DMEMIT("cache_evict[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.cache_evict));
    DMEMIT("free_cache_cnt[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.free_cache_cnt));
    DMEMIT("val_cache_cnt[%llu]\n",
           (uint64_t)atomic64_read(&dmc->stats.val_cache_cnt));
    DMEMIT("tree_cnt[%llu]\n", (uint64_t)atomic64_read(&dmc->stats.tree_cnt));
    break;
  case STATUSTYPE_TABLE:
    DMEMIT("cache capacity in blocks: [%llu]", dmc->cache_block_quantity);
    break;
  }
}


/*
 * Destroy the cache mapping.
 */
static void cache_dtr(struct dm_target *ti)
{
  struct dmc_c *dmc = (struct dmc_c *) ti->private;

  dm_kcopyd_client_destroy(dmc->kcp_client);

  // vfree((void *)dmc->cache_meta_array);
  dm_io_client_destroy(dmc->io_client);

  dm_put_device(ti, dmc->src_dev);
  dm_put_device(ti, dmc->cache_dev);
  kfree(dmc);
  DMC_INFO("Dm-cache destroy success.");
}

static struct target_type cache_target = {
  .name   = "cache",
  .version= {2, 0, 1},
  .module = THIS_MODULE,
  .ctr    = cache_ctr,
  .dtr    = cache_dtr,
  .map    = cache_map,
  .status = cache_status,
};

static int jobs_init(void)
{
  int r;
  job_cache = KMEM_CACHE(dmc_job_c, 0);
  if (!job_cache) return -ENOMEM;

  r = mempool_init_slab_pool(&job_pool, 128, job_cache);
  if (r) {
    pr_err("Error: Failed to create job pool!");
  }

  return 0;
}

static int __init dm_cache_init(void)
{
  int r;

  DMC_INFO("The gdcache begin to dm-cache init.");
  r = jobs_init();
  if (r){
    DMC_INFO("failed to initialize jobs pool");
    return r;
  }

  dmc_io_wq = create_singlethread_workqueue("dmc_io_wq");
  if (!dmc_io_wq) {
    DMC_ERR("Failed to start workqueue dmc_io_wq");
    return -ENOMEM;
  }
  INIT_WORK(&dmc_io_work, do_io_work_func);

  r = dm_register_target(&cache_target);
  if (r) {
    DMC_ERR("cache target registration failed: %d", r);
    destroy_workqueue(dmc_io_wq);
    return r;
  }

  return 0;
}

static void __exit dm_cache_exit(void)
{
  DMC_INFO("dm-cache remove.");
  dm_unregister_target(&cache_target);

  BUG_ON(!list_empty(&complete_jobs));
  BUG_ON(!list_empty(&io_jobs));

  //mempool_destroy(&job_pool);
  //kmem_cache_destroy(job_cache);
}

module_init(dm_cache_init);
module_exit(dm_cache_exit);

MODULE_DESCRIPTION(DM_NAME " cache target");
MODULE_AUTHOR("Ming Zhao <mingzhao99th@gmail.com>");
MODULE_LICENSE("GPL");
