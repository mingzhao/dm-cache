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

	if(bio->bi_private)
		complete(bio->bi_private);
}

static int do_bio_read(struct block_device *bi_bdev, sector_t block,struct page *page_read)
{
        struct bio *bio;
        unsigned int left, size;
        int req_size = 512;
        int e, len,i;
        struct page *page;


        DECLARE_COMPLETION(comp);

        bio = bio_alloc(GFP_KERNEL | __GFP_NOFAIL, BIO_MAX_PAGES);

         bio->bi_sector = block;
        bio->bi_bdev = bi_bdev;
        bio->bi_end_io = req_endio;
        bio->bi_rw = 0;
        bio->bi_private = &comp;

        left = req_size;
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
        wait_for_completion(&comp);

        for(i=0; i<bio->bi_vcnt; ++i){
                memcpy(kmap(page_read),kmap(bio->bi_io_vec[i].bv_page),req_size);
                __free_pages(bio->bi_io_vec[i].bv_page, SEG_SIZE_ORDER);
        }
        bio_put(bio);

        return req_size;
}



ssize_t req_d_write(struct file *f, const char __user *buf,
			size_t cnt, loff_t *off)
{
	int e, len;
	unsigned int left, size;
	
	struct bio *bio;
	struct io_req req;
	struct page *page;
	struct page *cache_page,*source_page;

	e = copy_from_user(&req, buf, sizeof(struct io_req));
	if(e!=0) return -EFAULT;
	
	left = req.size;
	
	struct block_device *cache_dev = lookup_bdev("/dev/sda6");
	struct block_device *source_dev = lookup_bdev("/dev/sda6");

	cache_page = alloc_pages(GFP_KERNEL | __GFP_NOFAIL, SEG_SIZE_ORDER);
	if(!cache_page) return -ENOMEM;
	memset(kmap(cache_page),0,SEG_SIZE_BYTES);

	source_page = alloc_pages(GFP_KERNEL | __GFP_NOFAIL, SEG_SIZE_ORDER);
	if(!source_page) return -ENOMEM;
	memset(kmap(source_page),0,SEG_SIZE_BYTES);

	do_bio_read(cache_dev,req.sector,cache_page);
	do_bio_read(source_dev,3,source_page);

	if(0==memcmp(kmap(cache_page),kmap(source_page),req.size)){	
		printk("block %llu are EQUALS\n",req.sector);
	}else{
		printk("block %llu are DIFFERENT\n",req.sector);
	}
	__free_pages(cache_page, SEG_SIZE_ORDER);
	__free_pages(source_page, SEG_SIZE_ORDER);

	return req.size;
}

ssize_t req_d_write1(struct file *f, const char __user *buf,
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
	bio->bi_bdev = lookup_bdev("/dev/sda6");
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
