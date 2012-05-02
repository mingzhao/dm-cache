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
	{ 0xdcbf2205, "module_layout" },
	{ 0xe74cf0a7, "mempool_destroy" },
	{ 0x563e3c5a, "dm_unregister_target" },
	{ 0xdb54a24b, "__alloc_workqueue_key" },
	{ 0xefade8fb, "destroy_workqueue" },
	{ 0xa064e9f8, "dm_register_target" },
	{ 0x482b49c8, "kmem_cache_destroy" },
	{ 0x26d6c0b6, "mempool_create" },
	{ 0x183fa88b, "mempool_alloc_slab" },
	{ 0x8a99a016, "mempool_free_slab" },
	{ 0x9ce94876, "kmem_cache_create" },
	{ 0x3e071ee1, "bio_clone" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x7c9437a7, "bio_endio" },
	{ 0xf09c7f68, "__wake_up" },
	{ 0xceecfd70, "mempool_free" },
	{ 0xc1c4e9e, "put_page" },
	{ 0x2fa5a500, "memcmp" },
	{ 0x42224298, "sscanf" },
	{ 0xe174aa7, "__init_waitqueue_head" },
	{ 0x9620b184, "dm_kcopyd_client_create" },
	{ 0xa8d2ecd4, "dm_io_client_create" },
	{ 0x83db27f0, "dm_get_device" },
	{ 0xfd113364, "dm_table_get_mode" },
	{ 0x1300d153, "kmem_cache_alloc_trace" },
	{ 0xb9c0a951, "kmalloc_caches" },
	{ 0x36828372, "dm_put_device" },
	{ 0xe212f1f5, "dm_io_client_destroy" },
	{ 0x999e8297, "vfree" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x78f72952, "dm_kcopyd_client_destroy" },
	{ 0xb00ccc33, "finish_wait" },
	{ 0xe75663a, "prepare_to_wait" },
	{ 0x1000e51, "schedule" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x93a6e0b2, "io_schedule" },
	{ 0x464c22a7, "current_task" },
	{ 0x36b14552, "queue_work" },
	{ 0x88941a06, "_raw_spin_unlock_irqrestore" },
	{ 0x587c70d8, "_raw_spin_lock_irqsave" },
	{ 0x3e090a79, "bio_put" },
	{ 0x83636ee3, "wait_for_completion" },
	{ 0xf5230a60, "bio_add_page" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xd01e4585, "alloc_pages_current" },
	{ 0xd4b25cd4, "bio_alloc" },
	{ 0x7bf44ee3, "dm_io" },
	{ 0x5e09ca75, "complete" },
	{ 0x37a0cba, "kfree" },
	{ 0xf2a05a2d, "__free_pages" },
	{ 0x4b77a92d, "generic_make_request" },
	{ 0xb2021c74, "dm_kcopyd_copy" },
	{ 0xef62e85f, "mempool_alloc" },
	{ 0xb85f3bbe, "pv_lock_ops" },
	{ 0x6443d74d, "_raw_spin_lock" },
	{ 0x27e1a049, "printk" },
	{ 0xe24050c7, "scnprintf" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "BEA5195E91A6DD5EA97384C");
