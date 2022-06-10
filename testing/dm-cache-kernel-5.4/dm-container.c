#include "dm-container.h"

int dmc_list_init(struct dmc_c *dmc, struct dmc_list_head_c *list)
{
  BUG_ON(dmc == NULL);
  BUG_ON(list == NULL);
  list->dmc = dmc;
  INIT_LIST_HEAD(&list->head);
  spin_lock_init(&list->lock);
  list->size = 0;
  return 0;
}

void dmc_list_insert_head(struct dmc_list_head_c *list,
                          struct cache_meta_c *node)
{
  BUG_ON(list == NULL);
  BUG_ON(node == NULL);
  spin_lock(&list->lock);
  node->rpl_head = list;
  list_add(&node->entry, &list->head);
  list->size++;
  spin_unlock(&list->lock);
}

void dmc_list_insert_tail(struct dmc_list_head_c *list,
                          struct cache_meta_c *node)
{
  BUG_ON(list == NULL);
  BUG_ON(node == NULL);
  spin_lock(&list->lock);
  node->rpl_head = list;
  list_add_tail(&node->entry, &list->head);
  list->size++;
  spin_unlock(&list->lock);
}

void dmc_list_move_head(struct cache_meta_c *node)
{
  struct dmc_list_head_c *list;
  BUG_ON(node == NULL);
  BUG_ON(node->rpl_head == NULL);
  list = node->rpl_head;
  BUG_ON(list->size == 0);
  spin_lock(&list->lock);
  list_move(&node->entry, &list->head);
  spin_unlock(&list->lock);
}

struct cache_meta_c *dmc_list_fetch_tail(struct dmc_list_head_c *list)
{
  struct cache_meta_c *tail_cache_node = NULL;
  if (list->size == 0) return NULL;
  spin_lock(&list->lock);
  tail_cache_node = list_last_entry(&list->head, struct cache_meta_c, entry);
  list_del(&tail_cache_node->entry);
  list->size--;
  spin_unlock(&list->lock);
  return tail_cache_node;
}
