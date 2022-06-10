#ifndef _RPL_LRU_H
#define _RPL_LRU_H

#include "dm-cache.h"

enum lru_list_name {
   LRU_NONE,
   LRU_LIST
};

struct dmc_lru_c {
  struct dmc_list_head_c lru_list;
  struct dmc_list_head_c free_list;
};

int lru_init(struct dmc_c *dmc);

int lru_destroy(struct dmc_c *dmc);

int lru_priotize_meta(struct dmc_job_c *job,
                      struct rpl_result_c *rpl_result);

#endif
