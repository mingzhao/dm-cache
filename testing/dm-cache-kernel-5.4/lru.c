#include "dm-cache.h"
#include "dm-container.h"
#include "lru.h"

static DEFINE_SPINLOCK(free_idx_lock);
#define FREE_IDX_LIST_LOCK		spin_lock(&free_idx_lock);
#define FREE_IDX_LIST_UNLOCK		spin_unlock(&free_idx_lock);

int lru_init(struct dmc_c *dmc)
{
  struct dmc_lru_c *dmc_lru;
  dmc_lru = (struct dmc_lru_c *)kmalloc(sizeof(struct dmc_lru_c), GFP_KERNEL);
  if (!dmc_lru) goto bad1;
  dmc_list_init(dmc, &dmc_lru->lru_list);
  dmc_list_init(dmc, &dmc_lru->free_list);
  dmc->rpl_c = (void *)dmc_lru;
  return 0;
bad1:
  DMC_ERR("***Dm-cache initialize LRU algotihm failed.");
  return -ENOMEM;
}

int lru_destroy(struct dmc_c *dmc)
{
  kfree(dmc->rpl_c);
  return 0;
}

int lru_priotize_meta(struct dmc_job_c *job,
                      struct rpl_result_c *res)
{
  struct dmc_lru_c *ctx = (struct dmc_lru_c *)job->dmc->rpl_c;
  struct dmc_list_head_c *lru_list = &ctx->lru_list;
  struct dmc_list_head_c *free_list = &ctx->free_list;
  struct dmc_c *dmc = job->dmc;
  struct cache_meta_c *free_cache_node = NULL;
  struct cache_meta_c *evict_cache_node = NULL;

  if (job->cache_node != NULL) {
    DMC_INFO_CACHE(job->cache_node, "Move item to HEAD");
    dmc_list_move_head(job->cache_node);
    res->write_cache_id = job->cache_node->cache_id;
    res->evict_meta = NULL;
    return 0;
  }

  BUG_ON(res == NULL);

  FREE_IDX_LIST_LOCK;
  // Fetches from the empty cache block index.
  if (dmc->free_idx < dmc->cache_block_quantity) {
    res->write_cache_id = dmc->free_idx;
    res->evict_meta = NULL;
    //job->cache_node = &dmc->cache_meta_array[dmc->free_idx];
    job->cache_node = mempool_alloc(&dmc->cache_metadata_pool, GFP_NOIO);
    job->cache_node->cache_id = dmc->free_idx;
    job->cache_node->data_id = job->src_data_id;
    job->cache_node->cache_state = INVALID;
    job->cache_node->rpl_head = lru_list;
    dmc_list_insert_head(lru_list, job->cache_node);
    DMC_INFO("Allocate FREE space from index %llu", dmc->free_idx);
    dmc->free_idx++;
    FREE_IDX_LIST_UNLOCK;
    return 0;
  }
  // Fetches the cache block from free list.
  free_cache_node = dmc_list_fetch_tail(free_list);
  if (free_cache_node != NULL) {
    res->write_cache_id = free_cache_node->cache_id;
    res->evict_meta = NULL;
    job->cache_node = free_cache_node;
    job->cache_node->data_id = job->src_data_id;
    job->cache_node->cache_state = INVALID;
    job->cache_node->rpl_head = lru_list;
    dmc_list_insert_head(lru_list, job->cache_node);
    DMC_INFO("Allocate FREE space from free list cache_id %llu",
             job->cache_node->cache_id);
    FREE_IDX_LIST_UNLOCK;
    return 0;
  }
  FREE_IDX_LIST_UNLOCK;

  // Fetches from cache_block from LRU tail.
  evict_cache_node = dmc_list_fetch_tail(lru_list);
  BUG_ON(evict_cache_node->cache_id == U64_MAX);
  res->write_cache_id = evict_cache_node->cache_id;
  res->evict_meta = evict_cache_node;
  job->cache_node = mempool_alloc(&dmc->cache_metadata_pool, GFP_NOIO);
  job->cache_node->cache_id = evict_cache_node->cache_id;
  job->cache_node->data_id = job->src_data_id;
  job->cache_node->cache_state = INVALID;
  job->cache_node->rpl_head = lru_list;
  dmc_list_insert_head(lru_list, job->cache_node);
  DMC_INFO("Allocate FREE space from LRU tail");
//  dmc_list_insert_head(lru_list, job->cache_node);
  return 0;
}
