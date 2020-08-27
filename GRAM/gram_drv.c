/*
 * RAM Block Device based of ZRAM by Nitin Gupta <ngupta@vflare.org>
 */

#define KMSG_COMPONENT "gram"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#ifdef CONFIG_GRAM_DEBUG
#define DEBUG
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/err.h>

#include "gram_drv.h"

/* Globals */

static int gram_major;
static struct gram *gram_devices;

/* Module parms */
static unsigned int num_devices = 1;

#define GRAM_ATTR_RO(name)									\
static ssize_t gram_attr_##name##_show(struct device *d,	\
				struct device_attribute *attr, char *b)		\
{															\
	struct gram *gram = dev_to_gram(d);						\
	return scnprintf(b, PAGE_SIZE, "%llu\n",				\
		(u64)atomic64_read(&gram->stats.name));				\
}															\
static struct device_attribute dev_attr_##name =			\
	__ATTR(name, S_IRUGO, gram_attr_##name##_show, NULL);


/* Prototypes */

// Creation //

/*
 * The init function is used for module initiation so this
 * in the same vain as a main function in a normal C program
 */
//int __init gram_init(void);

/*
 * This function is where disk is created
 * and the memeroy is allocated
 */
static int create_device(struct gram *gram, int device_id);

/*
 * Handles all of the gram I/O requests.
 */
static void gram_make_request(struct request_queue *queue, struct bio *bio);
static void __gram_make_request(struct gram *gram, struct bio *bio);

/*
 * Check if request is within bounds and aligned on gram logical blocks
 */
static inline int valid_io_request(struct gram *gram, struct bio *bio);


// Destruction //


/*
 * The exit function is ustart, end, bound;
 */

//void __exit gram_exit(void);

/*
 * This removes the disk from the system and cleans up any
 * ongoing procceses required by the disk
 */
static void destroy_device(struct gram *gram);


// Read/Write //


/*
 * Checks which read/write function is required
 * and calls appropriately
 */
int gram_bvec_rw (struct gram *gram, struct bio_vec *bvec, u32 index, int offset, struct bio *bio);

/*
 * Reads the memory pointed too
 */
static int gram_bvec_read(struct gram *gram, struct bio_vec *bvec,u32 index, int offset, struct bio *bio);

/*
 * Writes to the area of memory pointed too
 */
static int gram_bvec_write(struct gram *gram, struct bio_vec *bvec, u32 index, int offset);
/*
 * Checks to see if writting to a full page or not
 * @return 0 as true 1 as false
 */
int partial_io(struct bio_vec *bvec);

/*
 * Free a page of memory and protect concurrent access to the same
 * index entry
 */
static void gram_free_page(struct gram *gram, size_t index);

/*
 * Functions
 */
static inline int init_done(struct gram *gram)
{
	return gram->meta != NULL;
}

static inline struct gram *dev_to_gram(struct device *dev)
{
	return (struct gram *)dev_to_disk(dev)->private_data;
}

static ssize_t disksize_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct gram *gram = dev_to_gram(dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", gram->disksize);
}

static ssize_t initstate_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u32 val;
	struct gram *gram = dev_to_gram(dev);

	down_read(&gram->init_lock);
	val = init_done(gram);
	up_read(&gram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t orig_data_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct gram *gram = dev_to_gram(dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n",
		(u64)(atomic64_read(&gram->stats.pages_stored)) << PAGE_SHIFT);
}

static ssize_t mem_used_total_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val = 0;
	struct gram *gram = dev_to_gram(dev);

	down_read(&gram->init_lock);
	if (init_done(gram)) {
		struct gram_meta *meta = gram->meta;
		val = zs_get_total_pages(meta->mem_pool);
	}
	up_read(&gram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val << PAGE_SHIFT);
}

/*
 *	Flag Operations
 */
static int gram_test_flag(struct gram_meta *meta, u32 index,
			enum gram_pageflags flag)
{
	return meta->table[index].value & BIT(flag);
}

static void gram_set_flag(struct gram_meta *meta, u32 index,
			enum gram_pageflags flag)
{
	meta->table[index].value |= BIT(flag);
}

static void gram_clear_flag(struct gram_meta *meta, u32 index,
			enum gram_pageflags flag)
{
	meta->table[index].value &= ~BIT(flag);
}

static size_t gram_get_obj_size(struct gram_meta *meta, u32 index)
{
	return meta->table[index].value & (BIT(GRAM_FLAG_SHIFT) - 1);
}

static void gram_set_obj_size(struct gram_meta *meta,
					u32 index, size_t size)
{
	unsigned long flags = meta->table[index].value >> GRAM_FLAG_SHIFT;

	meta->table[index].value = (flags << GRAM_FLAG_SHIFT) | size;
}

static inline int is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
}

/*
 * Check if request is within bounds and aligned on gram logical blocks.
 */
static inline int valid_io_request(struct gram *gram, struct bio *bio)
{
	u64 start, end, bound, size;
	start = bio->bi_sector;
	size = bio->bi_size;
	/* unaligned request */
	if (unlikely(start & (GRAM_SECTOR_PER_LOGICAL_BLOCK - 1)))
		return 0;
	if (unlikely(size & (GRAM_LOGICAL_BLOCK_SIZE - 1)))
		return 0;

	
	end = start + (size >> SECTOR_SHIFT);
	bound = gram->disksize >> SECTOR_SHIFT;
	/* out of range range */
	if (unlikely(start >= bound || end > bound || start > end))
		return 0;

	/* I/O request is valid */
	return 1;
}

/*
 * Removal of allocation
 */ 
static void gram_meta_free(struct gram_meta *meta)
{
	zs_destroy_pool(meta->mem_pool);
	vfree(meta->table);
	kfree(meta);
}

/*
 * Allocation of memory
 */ 
static struct gram_meta *gram_meta_alloc(u64 disksize)
{
	size_t num_pages;
	struct gram_meta *meta = kmalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		goto out;

	num_pages = disksize >> PAGE_SHIFT;
	meta->table = vzalloc(num_pages * sizeof(*meta->table));
	if (!meta->table) {
		pr_err("Error allocating gram address table\n");
		goto free_meta;
	}

	meta->mem_pool = zs_create_pool(ZS_MM_RW,GFP_NOIO | __GFP_HIGHMEM);
	if (!meta->mem_pool) {
		pr_err("Error creating memory pool\n");
		goto free_table;
	}

	return meta;

free_table:
	vfree(meta->table);
free_meta:
	kfree(meta);
	meta = NULL;
out: //Is needed ??
	return meta;
}

static void update_position(u32 *index, int *offset, struct bio_vec *bvec)
{
	if (*offset + bvec->bv_len >= PAGE_SIZE)
		(*index)++;
	*offset = (*offset + bvec->bv_len) % PAGE_SIZE;
}

static int page_zero_filled(void *ptr)
{
	unsigned int pos;
	unsigned long *page;

	page = (unsigned long *)ptr;

	for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos])
			return 0;
	}

	return 1;
}

static void handle_zero_page(struct bio_vec *bvec)
{
	struct page *page = bvec->bv_page;
	void *user_mem;

	user_mem = kmap_atomic(page);
	if (is_partial_io(bvec))
		memset(user_mem + bvec->bv_offset, 0, bvec->bv_len);
	else
		clear_page(user_mem);
	kunmap_atomic(user_mem);

	flush_dcache_page(page);
}

static void gram_free_page(struct gram *gram, size_t index)
{
	struct gram_meta *meta = gram->meta;
	unsigned long handle = meta->table[index].handle;

	if (unlikely(!handle)) {
		/*
		 * No memory is allocated for zero filled pages.
		 * Simply clear zero page flag.
		 */
		if (gram_test_flag(meta, index, GRAM_ZERO)) {
			gram_clear_flag(meta, index, GRAM_ZERO);
			atomic64_dec(&gram->stats.zero_pages);
		}
		return;
	}

	zs_free(meta->mem_pool, handle);

	//atomic64_sub(gram_get_obj_size(meta, index),
	//		&gram->stats.compr_data_size);
	atomic64_dec(&gram->stats.pages_stored);

	meta->table[index].handle = 0;
	gram_set_obj_size(meta, index, 0);
}
static int gram_process_page(struct gram *gram, char *mem, u32 index)
{
	unsigned char *cmem;
	struct gram_meta *meta = gram->meta;
	unsigned long handle;
	size_t size;

	bit_spin_lock(GRAM_ACCESS, &meta->table[index].value);
	handle = meta->table[index].handle;
	size = gram_get_obj_size(meta, index);

	if (!handle || gram_test_flag(meta, index, GRAM_ZERO)) {
		bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);
		clear_page(mem);
		return 0;
	}

	cmem = zs_map_object(meta->mem_pool, handle, ZS_MM_RO);
	if (size == PAGE_SIZE)
		copy_page(mem, cmem);
	zs_unmap_object(meta->mem_pool, handle);
	bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);

	return 0;
}

static int gram_bvec_read(struct gram *gram, struct bio_vec *bvec,
			  u32 index, int offset, struct bio *bio)
{
	int ret;
	struct page *page;
	unsigned char *user_mem, *uncmem = NULL;
	struct gram_meta *meta = gram->meta;
	page = bvec->bv_page;

	bit_spin_lock(GRAM_ACCESS, &meta->table[index].value);
	if (unlikely(!meta->table[index].handle) ||
			gram_test_flag(meta, index, GRAM_ZERO)) {
	 	bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);
	 	handle_zero_page(bvec);
	 	return 0;
	}
	bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);

	if (is_partial_io(bvec))
	 	uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);

	user_mem = kmap_atomic(page);
	if (!is_partial_io(bvec))
		uncmem = user_mem;

	if (!uncmem) {
		pr_info("Unable to allocate temp memory\n");
		ret = -ENOMEM;
		goto out_cleanup;
	}
	gram_process_page(gram, uncmem, index);

	if (is_partial_io(bvec))
		memcpy(user_mem + bvec->bv_offset, uncmem + offset,
				bvec->bv_len);

	flush_dcache_page(page);
	ret = 0;
out_cleanup:
	kunmap_atomic(user_mem);
	if (is_partial_io(bvec))
		kfree(uncmem);
	return ret;
}

static inline void update_used_max(struct gram *gram,
					const unsigned long pages)
{
	int old_max, cur_max;

	old_max = atomic_long_read(&gram->stats.max_used_pages);

	do {
		cur_max = old_max;
		if (pages > cur_max)
			old_max = atomic_long_cmpxchg(
				&gram->stats.max_used_pages, cur_max, pages);
	} while (old_max != cur_max);
}

static int gram_bvec_write(struct gram *gram, struct bio_vec *bvec, u32 index,
			   int offset)
{
	int ret = 0;
	size_t clen;
	unsigned long handle;
	struct page *page;
	unsigned char *user_mem, *cmem, *src, *uncmem = NULL;
	struct gram_meta *meta = gram->meta;
	bool locked = false;
	unsigned long alloced_pages;

	page = bvec->bv_page;
	if (is_partial_io(bvec)) {
		/*
		* This is a partial IO. We need to read the full page
		* before to write the changes.
		*/
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);
		if (!uncmem) {
			ret = -ENOMEM;
			goto out;
		}
		ret = gram_process_page(gram, uncmem, index);
		if (ret)
			goto out;
	}

	locked = true;
	user_mem = kmap_atomic(page);

	if (is_partial_io(bvec)) {
		memcpy(uncmem + offset, user_mem + bvec->bv_offset,
		       bvec->bv_len);
		kunmap_atomic(user_mem);
		user_mem = NULL;
	} else {
		uncmem = user_mem;
	}

	if (page_zero_filled(uncmem)) {
		if (user_mem)
			kunmap_atomic(user_mem);
		/* Free memory associated with this sector now. */
		bit_spin_lock(GRAM_ACCESS, &meta->table[index].value);
		gram_free_page(gram, index);
		gram_set_flag(meta, index, GRAM_ZERO);
		bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);

		atomic64_inc(&gram->stats.zero_pages);
		ret = 0;
		goto out;
	}
	if (!is_partial_io(bvec)) {
		kunmap_atomic(user_mem);
		user_mem = NULL;
		uncmem = NULL;
	}
	clen = PAGE_SIZE;
	src = uncmem;

	handle = zs_malloc(meta->mem_pool, clen);
	if (!handle) {
		pr_info("Error allocating memory for page: %u, size=%zu\n",
			index, clen);
		ret = -ENOMEM;
		goto out;
	}

	alloced_pages = zs_get_total_pages(meta->mem_pool);
	update_used_max(gram, alloced_pages);

	cmem = zs_map_object(meta->mem_pool, handle, ZS_MM_WO);

	if ((clen == PAGE_SIZE) && !is_partial_io(bvec)) {
		src = kmap_atomic(page);
		copy_page(cmem, src);
		kunmap_atomic(src);
	} else {
		memcpy(cmem, src, clen);
	}

	locked = false;
	zs_unmap_object(meta->mem_pool, handle);

	/*
	* Free memory associated with this sector
	* before overwriting unused sectors.
	*/
	bit_spin_lock(GRAM_ACCESS, &meta->table[index].value);
	gram_free_page(gram, index);

	meta->table[index].handle = handle;
	gram_set_obj_size(meta, index, clen);
	bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);

	/* Update stats */
	atomic64_inc(&gram->stats.pages_stored);
out:
	if (is_partial_io(bvec))
		kfree(uncmem);
	return ret;
}


int gram_bvec_rw (struct gram *gram, struct bio_vec *bvec, u32 index, int offset, struct bio *bio)
{
	int ret;
	int rw = bio_data_dir(bio);

	if (rw == READ) {
		atomic64_inc(&gram->stats.num_reads);
		ret = gram_bvec_read(gram, bvec, index, offset, bio);
	} else {
		atomic64_inc(&gram->stats.num_writes);
		ret = gram_bvec_write(gram, bvec, index, offset);
	}
	
	return ret;
}

/*
 * gram_bio_discard - handler on discard request
 * @index: physical block index in PAGE_SIZE units
 * @offset: byte offset within physical block
 */
static void gram_bio_discard(struct gram *gram, u32 index,
			     int offset, struct bio *bio)
{
	size_t n = bio->bi_size;
	struct gram_meta *meta = gram->meta;

	/*
	* gram manages data in physical block size units. Because logical block
	* size isn't identical with physical block size on some arch, we
	* could get a discard request pointing to a specific offset within a
	* certain physical block.  Although we can handle this request by
	* reading that physiclal block and decompressing and partially zeroing
	* and re-compressing and then re-storing it, this isn't reasonable
	* because our intent with a discard request is to save memory.  So
	* skipping this logical block is appropriate here.
	*/
	if (offset) {
		if (n <= (PAGE_SIZE - offset))
			return;

		n -= (PAGE_SIZE - offset);
		index++;
	}

	while (n >= PAGE_SIZE) {
		bit_spin_lock(GRAM_ACCESS, &meta->table[index].value);
		gram_free_page(gram, index);
		bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);
		atomic64_inc(&gram->stats.notify_free);
		index++;
		n -= PAGE_SIZE;
	}
}

static void gram_reset_device(struct gram *gram, bool reset_capacity)
{
	size_t index;
	struct gram_meta *meta;

	down_write(&gram->init_lock);

	if (!init_done(gram)) {
		up_write(&gram->init_lock);
		return;
	}

	meta = gram->meta;
	/* Free all pages that are still in this gram device */
	for (index = 0; index < gram->disksize >> PAGE_SHIFT; index++) {
		unsigned long handle = meta->table[index].handle;
		if (!handle)
			continue;

		zs_free(meta->mem_pool, handle);
	}


	gram_meta_free(gram->meta);
	gram->meta = NULL;
	/* Reset stats */
	memset(&gram->stats, 0, sizeof(gram->stats));

	gram->disksize = 0;
	if (reset_capacity)
		set_capacity(gram->disk, 0);

	up_write(&gram->init_lock);

	/*
	 * Revalidate disk out of the init_lock to avoid lockdep splat.
	 * It's okay because disk's capacity is protected by init_lock
	 * so that revalidate_disk always sees up-to-date capacity.
	 */
	if (reset_capacity)
		revalidate_disk(gram->disk);
}

/*
 * Sysfs requires attributes useful if using proc
 */
static ssize_t disksize_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 disksize;
	struct gram_meta *meta;
	struct gram *gram = dev_to_gram(dev);
	int err;

	disksize = memparse(buf, NULL);
	if (!disksize)
		return -EINVAL;

	disksize = PAGE_ALIGN(disksize);
	meta = gram_meta_alloc(disksize);
	if (!meta)
		return -ENOMEM;


	down_write(&gram->init_lock);
	if (init_done(gram)) {
		pr_info("Cannot change disksize for initialized device\n");
		err = -EBUSY;
		goto out_destroy_comp;
	}

	gram->meta = meta;
	gram->disksize = disksize;
	set_capacity(gram->disk, gram->disksize >> SECTOR_SHIFT);
	up_write(&gram->init_lock);

	/*
	* Revalidate disk out of the init_lock to avoid lockdep splat.
	* It's okay because disk's capacity is protected by init_lock
	* so that revalidate_disk always sees up-to-date capacity.
	*/
	revalidate_disk(gram->disk);

	return len;

out_destroy_comp:
	up_write(&gram->init_lock);
	return err;
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int ret;
	unsigned short do_reset;
	struct gram *gram;
	struct block_device *bdev;

	gram = dev_to_gram(dev);
	bdev = bdget_disk(gram->disk, 0);

	if (!bdev)
		return -ENOMEM;

	/* Do not reset an active device! */
	if (bdev->bd_holders) {
		ret = -EBUSY;
		goto out;
	}

	ret = kstrtou16(buf, 10, &do_reset);
	if (ret)
		goto out;

	if (!do_reset) {
		ret = -EINVAL;
		goto out;
	}

	/* Make sure all pending I/O is finished */
	fsync_bdev(bdev);
	bdput(bdev);

	gram_reset_device(gram, true);
	return len;

out:
	bdput(bdev);
	return ret;
}

static void __gram_make_request(struct gram *gram, struct bio *bio)
{
	int i, offset;
	u32 index;
	struct bio_vec *bvec;

	index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
	offset = (bio->bi_sector &
		  (SECTORS_PER_PAGE - 1)) << SECTOR_SHIFT;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		gram_bio_discard(gram, index, offset, bio);
		bio_endio(bio, 0);
		return;
	}

	bio_for_each_segment(bvec, bio, i) {
		int max_transfer_size = PAGE_SIZE - offset;

		if (bvec->bv_len > max_transfer_size) {
		/*
		* gram_bvec_rw() can only make operation on a single
		* gram page. Split the bio vector.
		*/
			struct bio_vec bv;

			bv.bv_page = bvec->bv_page;
			bv.bv_len = max_transfer_size;
			bv.bv_offset = bvec->bv_offset;

			if (gram_bvec_rw(gram, &bv, index, offset, bio) < 0)
				goto out;

			bv.bv_len = bvec->bv_len - max_transfer_size;
			bv.bv_offset += max_transfer_size;
			if (gram_bvec_rw(gram, &bv, index + 1, 0, bio) < 0)
				goto out;
		} else
			if (gram_bvec_rw(gram, bvec, index, offset, bio) < 0)
				goto out;

		update_position(&index, &offset, bvec);
	}

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return;

out:
	bio_io_error(bio);
}

/*
 * Handler function for all gram I/O requests.
 */
static void gram_make_request(struct request_queue *queue, struct bio *bio)
{
	struct gram *gram = queue->queuedata;

	down_read(&gram->init_lock);
	if (unlikely(!init_done(gram)))
		goto error;

	if (!valid_io_request(gram, bio)) {
		atomic64_inc(&gram->stats.invalid_io);
		goto error;
	}

	__gram_make_request(gram, bio);
	up_read(&gram->init_lock);

	return;

error:
	up_read(&gram->init_lock);
	bio_io_error(bio);
}

static void gram_slot_free_notify(struct block_device *bdev,
				unsigned long index)
{
	struct gram *gram;
	struct gram_meta *meta;

	gram = bdev->bd_disk->private_data;
	meta = gram->meta;

	bit_spin_lock(GRAM_ACCESS, &meta->table[index].value);
	gram_free_page(gram, index);
	bit_spin_unlock(GRAM_ACCESS, &meta->table[index].value);
	atomic64_inc(&gram->stats.notify_free);
}

static const struct block_device_operations gram_devops = {
	.swap_slot_free_notify = gram_slot_free_notify,
	.owner = THIS_MODULE
};

static DEVICE_ATTR(disksize, S_IRUGO | S_IWUSR,disksize_show, disksize_store);
static DEVICE_ATTR(initstate, S_IRUGO, initstate_show, NULL);
static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_store);
static DEVICE_ATTR(orig_data_size, S_IRUGO, orig_data_size_show, NULL);
static DEVICE_ATTR(mem_used_total, S_IRUGO, mem_used_total_show, NULL);
GRAM_ATTR_RO(num_reads);
GRAM_ATTR_RO(num_writes);
GRAM_ATTR_RO(failed_reads);
GRAM_ATTR_RO(failed_writes);
GRAM_ATTR_RO(invalid_io);
GRAM_ATTR_RO(notify_free);
GRAM_ATTR_RO(zero_pages);

static struct attribute *gram_disk_attrs[] = {
	&dev_attr_disksize.attr,
	&dev_attr_initstate.attr,
	&dev_attr_reset.attr,
	&dev_attr_num_reads.attr,
	&dev_attr_num_writes.attr,
	&dev_attr_failed_reads.attr,
	&dev_attr_failed_writes.attr,
	&dev_attr_invalid_io.attr,
	&dev_attr_notify_free.attr,
	&dev_attr_zero_pages.attr,
	&dev_attr_orig_data_size.attr,
	&dev_attr_mem_used_total.attr,
	NULL,
};

static struct attribute_group gram_disk_attr_group = {
	.attrs = gram_disk_attrs,
};



static int create_device(struct gram *gram, int device_id)
{
	int ret = -ENOMEM;
	init_rwsem(&gram->init_lock);
	gram->queue = blk_alloc_queue(GFP_KERNEL);
	if (!gram->queue) {
		pr_err("Error allocating disk queue for device %d\n",
			device_id);
		goto out;
	}

	blk_queue_make_request(gram->queue, gram_make_request);
	gram->queue->queuedata = gram;

	 /* gendisk structure */
	gram->disk = alloc_disk(1);
	if (!gram->disk) {
		pr_warn("Error allocating disk structure for device %d\n",
			device_id);
		goto out_free_queue;
	}

	gram->disk->major = gram_major;
	gram->disk->first_minor = device_id;
	gram->disk->fops = &gram_devops;
	gram->disk->queue = gram->queue;
	gram->disk->private_data = gram;
	snprintf(gram->disk->disk_name, 16, "gram%d", device_id);
	/* Actual capacity set using syfs (/sys/block/gram<id>/disksize */
	set_capacity(gram->disk, 0);
	/* gram devices sort of resembles non-rotational disks */
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, gram->disk->queue);
	/*
 	 * To ensure that we always get PAGE_SIZE aligned
 	 * and n*PAGE_SIZED sized I/O requests.
 	 */
	blk_queue_physical_block_size(gram->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(gram->disk->queue,
					GRAM_LOGICAL_BLOCK_SIZE);
	blk_queue_io_min(gram->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(gram->disk->queue, PAGE_SIZE);
	gram->disk->queue->limits.discard_granularity = PAGE_SIZE;
	gram->disk->queue->limits.max_discard_sectors = UINT_MAX;
	/*
	 * gram_bio_discard() will clear all logical blocks if logical block
 	 * size is identical with physical block size(PAGE_SIZE). But if it is
	 * different, we will skip discarding some parts of logical blocks in
	 * the part of the request range which isn't aligned to physical block
 	 * size.  So we can't ensure that all discarded logical blocks are
 	 * zeroed.
	 */
	if (GRAM_LOGICAL_BLOCK_SIZE == PAGE_SIZE)
		gram->disk->queue->limits.discard_zeroes_data = 1;
	else
		gram->disk->queue->limits.discard_zeroes_data = 0;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, gram->disk->queue);

	add_disk(gram->disk);

	ret = sysfs_create_group(&disk_to_dev(gram->disk)->kobj,
				&gram_disk_attr_group);
	if (ret < 0) {
		pr_warn("Error creating sysfs group");
		goto out_free_disk;
	}
	gram->meta = NULL;
	return 0;

out_free_disk:
	del_gendisk(gram->disk);
	put_disk(gram->disk);
out_free_queue:
	blk_cleanup_queue(gram->queue);
out:
	return ret;
}

static void destroy_device(struct gram *gram)
{
	sysfs_remove_group(&disk_to_dev(gram->disk)->kobj,
			&gram_disk_attr_group);

	del_gendisk(gram->disk);
	put_disk(gram->disk);

	blk_cleanup_queue(gram->queue);
}

static int __init gram_init(void)
{
	int ret, dev_id;

	if (num_devices > max_num_devices) {
		pr_warn("Invalid value for num_devices: %u\n",
				num_devices);
		ret = -EINVAL;
		goto out;
	}

	gram_major = register_blkdev(0, "gram");
	if (gram_major <= 0) {
		pr_warn("Unable to get major number\n");
		ret = -EBUSY;
		goto out;
	}

	/* Allocate the device array and initialize each one */
	gram_devices = kzalloc(num_devices * sizeof(struct gram), GFP_KERNEL);
	if (!gram_devices) {
		ret = -ENOMEM;
		goto unregister;
	}

	for (dev_id = 0; dev_id < num_devices; dev_id++) {
		ret = create_device(&gram_devices[dev_id], dev_id);
		if (ret)
			goto free_devices;
	}

	pr_info("Created %u device(s) ...\n", num_devices);

	return 0;

free_devices:
	while (dev_id)
		destroy_device(&gram_devices[--dev_id]);
	kfree(gram_devices);
unregister:
	unregister_blkdev(gram_major, "gram");
out:
	return ret;
}

static void __exit gram_exit(void)
{
	int i;
	struct gram *gram;

	for (i = 0; i < num_devices; i++) {
		gram = &gram_devices[i];

		destroy_device(gram);
		/*
 		 * Shouldn't access gram->disk after destroy_device
 		 * because destroy_device already released gram->disk.
 		 */
		gram_reset_device(gram, false);
	}

	unregister_blkdev(gram_major, "gram");

	kfree(gram_devices);
	pr_debug("Cleanup done!\n");
}

module_init(gram_init);
module_exit(gram_exit);

module_param(num_devices, uint, 0);
MODULE_PARM_DESC(num_devices, "Number of gram devices");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gabryel Mason-Williams <gabryel.mason-williams@diamond.ac.uk> \
							Dave Bond <dave.bond@diamond.ac.uk> \
							Mark Basham <mark.basham@rfi.ac.uk>");
MODULE_DESCRIPTION("RAM Block Device based of ZRAM by Nitin Gupta <ngupta@vflare.org>");
