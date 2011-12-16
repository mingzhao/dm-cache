#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>

#include <linux/bio.h>
#include <asm/errno.h>
#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/atomic.h>
#include <linux/completion.h>

#include <linux/blkdev.h>

MODULE_LICENSE("Dual BSD/GPL");

#define DEV_NAME "dev_req"
#define BIO_RW_SYNCIO   3

#define SEG_SIZE_ORDER	4 /* allocate segments of size 64KB */
#define SEG_SIZE_BYTES	((1U<<SEG_SIZE_ORDER)*PAGE_SIZE)

/* func operations */
ssize_t req_d_write(struct file *f, const char __user *buf,
			size_t cnt, loff_t *off);

/* char dev information */
static dev_t req_d;
static struct class *req_class;
static struct cdev req_cdev = {
	.owner = THIS_MODULE,
};
static struct file_operations req_d_ops = {
	.write = req_d_write,
};

struct io_req {
	unsigned int sector;
	unsigned long rw;
	unsigned int size;
	unsigned int major;
	unsigned int minor;
	unsigned int sync;
};

static void req_endio(struct bio *bio, int err)
{
	int i;
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);

	BUG_ON(!uptodate);

	for(i=0; i<bio->bi_vcnt; ++i)
		__free_pages(bio->bi_io_vec[i].bv_page, SEG_SIZE_ORDER);

	bio_put(bio);

	if(bio->bi_private)
		complete(bio->bi_private);
}

ssize_t req_d_write(struct file *f, const char __user *buf,
			size_t cnt, loff_t *off)
{
	int e, len;
	unsigned int left, size;
	
	struct bio *bio;
	struct io_req req;
	struct page *page;

	DECLARE_COMPLETION(comp);

	e = copy_from_user(&req, buf, sizeof(struct io_req));
	if(e!=0) return -EFAULT;
	
	left = req.size;
	
	bio = bio_alloc(GFP_KERNEL | __GFP_NOFAIL, BIO_MAX_PAGES);
	if(!bio) return -ENOMEM;
	
	bio->bi_sector = req.sector;
	//bio->bi_bdev = bdget(MKDEV(req.major,req.minor));
	bio->bi_bdev = lookup_bdev("/dev/mapper/cache2");
	bio->bi_end_io = req_endio;
	bio->bi_rw = req.rw | (1<<BIO_RW_SYNCIO);
	bio->bi_private = req.sync?&comp:NULL;
	if(!bio->bi_bdev->bd_disk)
		blkdev_get(bio->bi_bdev,FMODE_WRITE, NULL);
	
	while(left > 0) {
		/* allocate contigous pages */
		page = alloc_pages(GFP_KERNEL | __GFP_NOFAIL, SEG_SIZE_ORDER);
		if(!page) return -ENOMEM;

		/* fill all pages with 0 */
		memset(kmap(page),0,SEG_SIZE_BYTES);
		
		size = (left>SEG_SIZE_BYTES) ? SEG_SIZE_BYTES : left;
		
		len = bio_add_page(bio, page, size, 0);
		BUG_ON(len != size);

		left -= size;
	}
	/* submit the bio */
	generic_make_request(bio);
	if(req.sync)
		wait_for_completion(&comp);

	return req.size;
}

static int dev_req_init(void)
{
	int e;

	/* allocate chrdev */
	e = alloc_chrdev_region(&req_d, 0, 1, DEV_NAME);
	if(e < 0) return e;
	
	/* register chrdev */
	cdev_init(&req_cdev, &req_d_ops);
	e = cdev_add(&req_cdev, req_d, 1);
	
	/* create device file */
	req_class = class_create(THIS_MODULE, "req");
	if(IS_ERR(req_class)) return -1;
	
	device_create(req_class, NULL, req_d, DEV_NAME,"dev_req");
	
	printk("dev_req module initialized\n");

	return 0;
}

static void dev_req_exit(void)
{
	/* unregister chrdev */
	device_destroy(req_class, req_d);
	class_destroy(req_class);
	cdev_del(&req_cdev);

	/* deallocate chrdev */
	unregister_chrdev_region(req_d, 1);

	printk("dev_req unloaded\n");
}

module_init(dev_req_init);
module_exit(dev_req_exit);
