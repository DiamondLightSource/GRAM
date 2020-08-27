/*
 * RAM Block Device based of ZRAM by Nitin Gupta <ngupta@vflare.org>
 */

#ifndef GRAM_DRV_H
#define GRAM_DRV_H

#include <linux/spinlock.h>
#include <linux/zsmalloc.h>

/*
 * Some value, this is just to catch invalid 
 * value for num_devices module parameter
 */

static const unsigned max_num_devices = 999;

#define SECTOR_SHIFT 	9
#define SECTORS_PER_PAGE_SHIFT 	(PAGE_SHIFT - SECTOR_SHIFT)
#define SECTORS_PER_PAGE 		(1 <<SECTORS_PER_PAGE_SHIFT)
#define GRAM_LOGICAL_BLOCK_SHIFT 12
#define GRAM_LOGICAL_BLOCK_SIZE	(1 << GRAM_LOGICAL_BLOCK_SHIFT)
#define GRAM_SECTOR_PER_LOGICAL_BLOCK	\
	(1 << (GRAM_LOGICAL_BLOCK_SHIFT - SECTOR_SHIFT))


/*
 * The lower gram_FLAG_SHIFT bits of table.value is for
 * object size (excluding header), the higher bits is for
 * gram_pageflags.
 *
 * gram is mainly used for memory efficiency so we want to keep memory
 * footprint small so we can squeeze size and flags into a field.
 * The lower gram_FLAG_SHIFT bits is for object size (excluding header),
 * the higher bits is for gram_pageflags.
 */

#define GRAM_FLAG_SHIFT 24

/* Flags for gram pages (table[page_no].value) */
enum gram_pageflags {
	/* Page consists entirely of zeros */
	GRAM_ZERO = GRAM_FLAG_SHIFT,
	GRAM_ACCESS,	/* page is now accessed */

	__NR_GRAM_PAGEFLAGS,
};

/* Data structures */

/* Allocated for each disk page */
struct gram_table_entry {
	unsigned long handle;
	unsigned long value;
};

struct gram_stats {
	atomic64_t num_reads;			/* failed + successful */
	atomic64_t num_writes;			/* no. of writes */
	atomic64_t failed_reads;		/* can happen when memory is too low */
	atomic64_t failed_writes;		/* can happen when memory is too low */
	atomic64_t invalid_io;			/* non-page-aligned I/O requests */
	atomic64_t notify_free;			/* no. of swap slot free notifications */
	atomic64_t zero_pages;			/* no. of zero filled pages */
	atomic64_t pages_stored;		/* no. of pages currently stored */
	atomic_long_t max_used_pages;	/* no. of maximum pages stored */
};

struct gram_meta {
	struct gram_table_entry *table;
	struct zs_pool *mem_pool;
};

struct gram {
	struct gram_meta *meta;
	struct gendisk *disk;
	struct request_queue *queue;
	/* Prevent concurrent execution of device init */
	struct rw_semaphore init_lock;
	struct gram_stats stats;
	atomic_t refcount; /* refcount for gram_meta */
	/* wait all IO under all of cpu are done */
	wait_queue_head_t io_done;
	/*
	 * This is the limit on amount of data
	 * that can be stored in a disk.
 	 */
	u64 disksize;	/* bytes */
	void *buffer;
	void *private;
	struct list_head list;
};
#endif

