#ifndef _DMC_CONTAINER_H_
#define _DMC_CONTAINER_H_

#include "dm-cache.h"

int dmc_list_init(struct dmc_c *dmc, struct dmc_list_head_c *list);

void dmc_list_insert_head(struct dmc_list_head_c *list,
                          struct cache_meta_c *cache_node);

void dmc_list_insert_tail(struct dmc_list_head_c *list,
                          struct cache_meta_c *node);

void dmc_list_move_head(struct cache_meta_c *node);

struct cache_meta_c *dmc_list_fetch_tail(struct dmc_list_head_c *list);

#endif
