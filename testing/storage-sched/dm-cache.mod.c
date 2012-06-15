#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa7bb2905, "module_layout" },
	{ 0x5f27544a, "mempool_destroy" },
	{ 0x867b2afa, "dm_unregister_target" },
	{ 0x88a193, "__alloc_workqueue_key" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x5eb40045, "dm_register_target" },
	{ 0x9602b755, "kmem_cache_destroy" },
	{ 0xd266efe7, "mempool_create" },
	{ 0x183fa88b, "mempool_alloc_slab" },
	{ 0x8a99a016, "mempool_free_slab" },
	{ 0x8f18d118, "kmem_cache_create" },
	{ 0x6188ccc6, "__alloc_pages_nodemask" },
	{ 0x5f12014b, "contig_page_data" },
	{ 0x35ca8cfa, "dm_kcopyd_client_create" },
	{ 0x601f665f, "dm_io_client_create" },
	{ 0x91715312, "sprintf" },
	{ 0x42224298, "sscanf" },
	{ 0x48eb0c0d, "__init_waitqueue_head" },
	{ 0xde41d2ad, "blkdev_get" },
	{ 0x31c83ae6, "lookup_bdev" },
	{ 0x16000a3c, "dm_device_name" },
	{ 0x43f23311, "dm_table_get_md" },
	{ 0x5abb52b1, "dm_get_device" },
	{ 0x6d0f1f89, "dm_table_get_mode" },
	{ 0xe914e41e, "strcpy" },
	{ 0xc312a44a, "kmem_cache_alloc_trace" },
	{ 0xf4f822d3, "kmalloc_caches" },
	{ 0x86a4889a, "kmalloc_order_trace" },
	{ 0x8ef193a6, "blkdev_put" },
	{ 0x9e4faeef, "dm_io_client_destroy" },
	{ 0x999e8297, "vfree" },
	{ 0x7d50a24, "csum_partial" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x154c6338, "dm_kcopyd_client_destroy" },
	{ 0x82f6b2d, "dm_put_device" },
	{ 0x75bb675a, "finish_wait" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0x4292364c, "schedule" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x93a6e0b2, "io_schedule" },
	{ 0xe99d09f, "current_task" },
	{ 0x33543801, "queue_work" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xde90811f, "dm_io" },
	{ 0xa67da660, "mempool_alloc" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0xfa30957c, "mempool_free" },
	{ 0x570eff52, "bio_endio" },
	{ 0x37a0cba, "kfree" },
	{ 0xe7639f58, "__free_pages" },
	{ 0x39aea914, "dm_kcopyd_copy" },
	{ 0xf9e73082, "scnprintf" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x50eedeb8, "printk" },
	{ 0x1b10e5f4, "generic_make_request" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "6983B0C982526DFE3AE1009");
