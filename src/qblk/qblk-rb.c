#include <linux/circ_buf.h>

#include "qblk.h"

//declaration lock
static DECLARE_RWSEM(qblk_rb_lock);


#define qblk_rb_ring_count(head, tail, size) CIRC_CNT(head, tail, size)
#define qblk_rb_ring_space(rb, head, tail, size) \
					(CIRC_SPACE(head, tail, size))

unsigned int qblk_rb_sync_init(struct qblk_rb *rb, unsigned long *flags)
	__acquires(&rb->s_lock)
{
	if (flags)
		spin_lock_irqsave(&rb->s_lock, *flags);
	else
		spin_lock_irq(&rb->s_lock);

	//return rb->sync;
	return READ_ONCE(rb->sync);
}

void qblk_rb_sync_end(struct qblk_rb *rb, unsigned long *flags)
	__releases(&rb->s_lock)
{
	lockdep_assert_held(&rb->s_lock);

	if (flags)
		spin_unlock_irqrestore(&rb->s_lock, *flags);
	else
		spin_unlock_irq(&rb->s_lock);
}

unsigned int qblk_rb_sync_advance(struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int sync, flush_point;

	lockdep_assert_held(&rb->s_lock);

	sync = READ_ONCE(rb->sync);

	spin_lock(&rb->fp_write_lock);
	flush_point = atomic_read_acquire(&rb->flush_point);

	//pr_notice("%s,sync=%u,flushpoint=%u\n",
	//			__func__, sync, flush_point);

	if (flush_point != EMPTY_ENTRY) {
		unsigned int secs_to_flush;

		secs_to_flush = qblk_rb_ring_count(flush_point, sync,
					rb->nr_entries);

		//If they're equal, we have one more entry to flush.
		if (secs_to_flush < nr_entries)
			atomic_set_release(&rb->flush_point, EMPTY_ENTRY);
	}
	spin_unlock(&rb->fp_write_lock);

	sync = (sync + nr_entries) & (rb->nr_entries - 1);

	/* Protect from counts */
	smp_store_release(&rb->sync, sync);
	//pr_notice("%s,sync=%u stored\n",__func__,sync);

	return sync;
}

static struct qblk_persist_work *qblk_persist_work_alloc_init(struct request *req,
																unsigned int nr_rb)
{
	unsigned int i;

	struct qblk_persist_work *persist_work =
			(struct qblk_persist_work *)kmalloc(sizeof(*persist_work), GFP_ATOMIC);

	if (!persist_work)
		return NULL;
	spin_lock_init(&persist_work->lock);
	persist_work->req = req;
	persist_work->persist_bm = bitmap_zalloc(nr_rb, GFP_ATOMIC);
	if (!persist_work->persist_bm)
		goto errOut;

	persist_work->per_rb_pws = kmalloc_array(nr_rb,
								sizeof(struct qblk_per_rb_pw),
								GFP_ATOMIC);
	if (!persist_work->per_rb_pws)
		goto errOut2;

	for (i = 0; i < nr_rb; i++)
		persist_work->per_rb_pws[i].pw = persist_work;

	return persist_work;
errOut2:
	bitmap_free(persist_work->persist_bm);
errOut:
	kfree(persist_work);
	return NULL;
}

void qblk_persist_work_release(struct qblk_persist_work *persist_work)
{
	kvfree(persist_work->per_rb_pws);
	bitmap_free(persist_work->persist_bm);
	kvfree(persist_work);
}

/*
 * Buffer count is calculated with respect to the submission entry signaling the
 * entries that are available to send to the media
 */
unsigned int qblk_rb_read_count(struct qblk_rb *rb)
{
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int subm = READ_ONCE(rb->subm);

	return qblk_rb_ring_count(mem, subm, rb->nr_entries);
}

unsigned int qblk_rb_read_count_for_drain(struct qblk_rb *rb)
{
	unsigned int mem;
	unsigned int subm;

	mem = READ_ONCE(rb->mem);
	subm = READ_ONCE(rb->subm);

	return qblk_rb_ring_count(mem, subm, rb->nr_entries);
}


unsigned int qblk_rb_sync_count(struct qblk_rb *rb)
{
	unsigned int mem = READ_ONCE(rb->mem);
	unsigned int sync = READ_ONCE(rb->sync);

	return qblk_rb_ring_count(mem, sync, rb->nr_entries);
}

unsigned int qblk_rb_read_commit(struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int subm;

	subm = READ_ONCE(rb->subm);
	/* Commit read means updating submission pointer */
	smp_store_release(&rb->subm,
				(subm + nr_entries) & (rb->nr_entries - 1));

	return subm;
}

inline struct qblk_rb_entry *qblk_rb_entry_by_pos(struct qblk_rb *rb, unsigned int pos)
{
	return &rb->entries[pos & (rb->nr_entries - 1)];
}

struct qblk_w_ctx *qblk_rb_w_ctx(struct qblk_rb *rb, unsigned int pos)
{
	unsigned int entry = pos & (rb->nr_entries - 1);

	return &rb->entries[entry].w_ctx;
}

/* Calculate how many sectors to submit up to the current flush point. */
unsigned int qblk_rb_flush_point_count(struct qblk_rb *rb, unsigned int flush_point)
{
	unsigned int subm, sync;
	unsigned int submitted, to_flush;

	/* Protect flush points */
	if (flush_point == EMPTY_ENTRY)
		return 0;

	/* Protect syncs */
	sync = smp_load_acquire(&rb->sync);

	subm = READ_ONCE(rb->subm);
	submitted = qblk_rb_ring_count(subm, sync, rb->nr_entries);

	/* The sync point itself counts as a sector to sync */
	to_flush = qblk_rb_ring_count(flush_point, sync, rb->nr_entries) + 1;

	return (submitted < to_flush) ? (to_flush - submitted) : 0;
}

void qblk_rb_set_flush_point(struct qblk_rb *rb, unsigned int new_point)
{
	unsigned int sync;
	unsigned int old_to_flush, new_to_flush;
	unsigned int flush_point;

	lockdep_assert_held(&rb->fp_write_lock);
	flush_point = atomic_read_acquire(&rb->flush_point);

	/* Protect flush points */
	if (flush_point == EMPTY_ENTRY) {
		atomic_set_release(&rb->flush_point, new_point);
		return;
	}

	sync = smp_load_acquire(&rb->sync);
	old_to_flush = qblk_rb_ring_count(flush_point, sync, rb->nr_entries);
	new_to_flush = qblk_rb_ring_count(new_point, sync, rb->nr_entries);

	if (new_to_flush > old_to_flush)
		atomic_set_release(&rb->flush_point, new_point);
}


static void clean_wctx(struct qblk_w_ctx *w_ctx)
{
	int flags;

try:
	flags = READ_ONCE(w_ctx->flags);
	if (!(flags & QBLK_SUBMITTED_ENTRY))
		goto try;

	/* Release flags on context. Protect from writes and reads */
	smp_store_release(&w_ctx->flags, QBLK_WRITABLE_ENTRY);
	qblk_ppa_set_empty(&w_ctx->ppa);
	w_ctx->lba = ADDR_EMPTY;
}

static int __qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int to_update)
{
	struct qblk_line *line;
	struct qblk_rb_entry *entry;
	struct qblk_w_ctx *w_ctx;
	unsigned int user_io = 0, gc_io = 0;
	unsigned int i;
	int flags;

	for (i = 0; i < to_update; i++) {
		entry = &rb->entries[rb->l2p_update];
		w_ctx = &entry->w_ctx;

		flags = READ_ONCE(entry->w_ctx.flags);
		if (flags & QBLK_IOTYPE_USER)
			user_io++;
		else if (flags & QBLK_IOTYPE_GC)
			gc_io++;
		else
			WARN(1, "qblk: unknown IO type\n");

		qblk_update_map_dev(qblk, w_ctx->lba, w_ctx->ppa,
							entry->cacheline);
		line = qblk_ppa_to_structline(qblk, w_ctx->ppa);
		kref_put(&line->ref, qblk_line_put);
		//pr_notice("%s,put the reference of line[%u]\n",__func__,line->id);
		clean_wctx(w_ctx);
		rb->l2p_update = (rb->l2p_update + 1) & (rb->nr_entries - 1);
	}

	qblk_rl_out(&qblk->rl,
			user_io, gc_io);

	return 0;
}


/*
 * When we move the l2p_update pointer, we update the l2p table - lookups will
 * point to the physical address instead of to the cacheline in the write buffer
 * from this moment on.
 */
static int qblk_rb_update_l2p(struct qblk *qblk, struct qblk_rb *rb, unsigned int nr_entries,
			      unsigned int mem, unsigned int sync)
{
	unsigned int space, count;
	int ret = 0;

	lockdep_assert_held(&rb->w_lock);

	/* Update l2p only as buffer entries are being overwritten */
	space = qblk_rb_ring_space(rb, mem, rb->l2p_update, rb->nr_entries);
	if (space > nr_entries)
		goto out;

	count = nr_entries - space;
	/* l2p_update used exclusively under rb->w_lock */
	ret = __qblk_rb_update_l2p(qblk, rb, count);

out:
	return ret;
}

/*
 * Update the l2p entry for all sectors stored on the write buffer. This means
 * that all future lookups to the l2p table will point to a device address, not
 * to the cacheline in the write buffer.
 */
static void qblk_rb_sync_l2p(struct qblk *qblk, struct qblk_rb *rb)
{
	unsigned int sync;
	unsigned int to_update;

	spin_lock(&rb->w_lock);

	/* Protect from reads and writes */
	sync = smp_load_acquire(&rb->sync);

	to_update = qblk_rb_ring_count(sync, rb->l2p_update, rb->nr_entries);
	__qblk_rb_update_l2p(qblk, rb, to_update);

	spin_unlock(&rb->w_lock);
}

void qblk_rb_sync_all_l2p(struct qblk *qblk)
{
	unsigned int queue_count = qblk->nr_queues;
	while (queue_count--)
		qblk_rb_sync_l2p(qblk, &qblk->mqrwb[queue_count]);
}

/* Check whether the rb have enough space for the comming request.
 * Return:
 * 0: space is sufficient.
 * n: space is in-sufficient.
 *    n = rb->nr_entries;
 */
static int __qblk_rb_maynot_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries)
{
	unsigned int mem;
	unsigned int sync;

	sync = READ_ONCE(rb->sync);
	mem = READ_ONCE(rb->mem);

	//pr_notice("%s:sync=0x%x,mem=0x%x\n",__func__,sync,mem);

	if (qblk_rb_ring_space(rb, mem, sync, rb->nr_entries) < nr_entries)
		return rb->nr_entries;

	if (qblk_rb_update_l2p(qblk, rb, nr_entries, mem, sync))
		return rb->nr_entries;

	return 0;
}

static void qblk_rb_persist_point_set(struct qblk *qblk,
					unsigned int rb_index,
					struct qblk_rb *rb,
					struct qblk_persist_work *persist_work)
{
	struct qblk_rb_entry *entry;
	unsigned int sync, persist_point;
	unsigned long flags;
	unsigned int pos;

	qblk_rb_sync_init(rb, &flags);
	spin_lock(&rb->fp_write_lock);
	pos = READ_ONCE(rb->mem);
	sync = READ_ONCE(rb->sync);
	
	//pr_notice("%s, rb(%u) pos=%u sync=%u\n",
	//			__func__, rb->rb_index, pos, sync);

	if (pos >= rb->nr_entries || sync >= rb->nr_entries) {
		spin_unlock(&rb->fp_write_lock);
		qblk_rb_sync_end(rb, &flags);
		return;
	}

	if (pos == sync) {
		spin_unlock(&rb->fp_write_lock);
		qblk_end_persist_point(rb, qblk, persist_work);
		qblk_rb_sync_end(rb, &flags);
		return;
	}

	persist_point = (0 == pos) ? (rb->nr_entries - 1) : (pos - 1);
	entry = &rb->entries[persist_point];

	/* Here, since we've already hold the rb->s_lock,
	 * the draining thread will not be able to move the
	 * sync pointer. Thus, we're save to set
	 * any entry's persist list.
	 */

	list_add(&persist_work->per_rb_pws[rb_index].list , &entry->w_ctx.persist_list);
	qblk_rb_set_flush_point(rb, persist_point);
	spin_unlock(&rb->fp_write_lock);
	qblk_rb_sync_end(rb, &flags);
}

static int qblk_rb_may_write(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
			    unsigned int *pos)
{
	unsigned int mem = READ_ONCE(rb->mem);

	*pos = mem;
	if (__qblk_rb_maynot_write(qblk, rb, nr_entries))
		return 0;

	/* Protect from read count */
	smp_store_release(&rb->mem, (*pos + nr_entries) & (rb->nr_entries - 1));
	return 1;
}

static int qblk_rb_maynot_write_flush(struct qblk *qblk,
				struct qblk_rb *rb, unsigned int nr_entries,
				unsigned int *pos, struct bio *bio,
				struct request *req)
{
	unsigned int old_mem, mem;
	int ret = 0;
	unsigned int request_flags = req->cmd_flags;

	*pos = old_mem = READ_ONCE(rb->mem);

	ret = __qblk_rb_maynot_write(qblk, rb, nr_entries);
	if (ret)
		return ret;

	mem = (*pos + nr_entries) & (rb->nr_entries - 1);

	/* Blk-mq guarantees that we'll not find REQ_PREFLUSH here */
	WARN_ON(request_flags & REQ_PREFLUSH);
#ifndef IGNORE_FUA
	if (request_flags & REQ_FUA) {
		unsigned int fua_point =
			(old_mem + nr_entries -1) & (rb->nr_entries - 1);
		unsigned long flags;

		/* __qblk_rb_maynot_write() guarantees that we have enough space for
		 * this req.
		 */
		rb->entries[fua_point].w_ctx.fua_req = req;
		spin_lock_irqsave(&rb->fp_write_lock, flags);
		qblk_rb_set_flush_point(rb, fua_point);
		spin_unlock_irqrestore(&rb->fp_write_lock, flags);

		ret = -1;//Don't end this request because the data is not persisted yet.
	}
#endif
	/* Protect from read count */
	smp_store_release(&rb->mem, mem);

	return ret;
}

/*
 * Atomically check that (i) there is space on the write buffer for the
 * incoming I/O, and (ii) the current I/O type has enough budget in the write
 * buffer (rate-limiter).
 * Return value:
 * 0: OK
 * 1: Rate limiter may not insert, or not enough mem space for qblk_rb_maynot_write_flush()
 * >1: Not enough space for ring buffer. See __qblk_rb_maynot_write();
 * -1: OK, but this is an FUA request, don't finish this request.
 * -2: Err
 */
int qblk_rb_may_write_user(struct qblk *qblk,
				unsigned int rbid,
				struct qblk_rb *rb, struct bio *bio,
				unsigned int nr_entries, unsigned int *pos, struct request *req)
{
	int ret;

	if (qblk_rl_user_maynot_insert(qblk, nr_entries))
		return 1;

	spin_lock(&rb->w_lock);

	ret = qblk_rb_maynot_write_flush(qblk, rb, nr_entries, pos, bio, req);
	if (ret < -1 || ret > 0) {
		spin_unlock(&rb->w_lock);
		return ret;
	}
	
	qblk_rl_user_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

	return ret;
}

/*
 * Write @nr_entries to ring buffer from @data buffer if there is enough space.
 * Typically, 4KB data chunks coming from a bio will be copied to the ring
 * buffer, thus the write will fail if not all incoming data can be copied.
 *
 */
static void __qblk_rb_write_entry(struct qblk_rb *rb, void *data,
					unsigned long metadata,
				  struct qblk_w_ctx w_ctx,
				  struct qblk_rb_entry *entry)
{
	memcpy(entry->data, data, rb->seg_size);

	entry->w_ctx.lba = w_ctx.lba;
	entry->w_ctx.ppa = w_ctx.ppa;
	entry->metadata = metadata;
}

void qblk_rb_write_entry_user(struct qblk *qblk,
				struct qblk_rb *rb, void *data,
				unsigned long metadata,
				struct qblk_w_ctx w_ctx, unsigned int ring_pos)
{
	struct qblk_rb_entry *entry;
	int flags;

	entry = &rb->entries[ring_pos];
	flags = READ_ONCE(entry->w_ctx.flags);
	//---
#if 0
#ifdef CONFIG_NVM_DEBUG
	/* Caller must guarantee that the entry is free */
	BUG_ON(!(flags & QBLK_WRITABLE_ENTRY));
#endif
#endif
	//pr_notice("%s,ringpos=%u\n",__func__,ring_pos);
	//printPageSample(data);

	__qblk_rb_write_entry(rb, data, metadata, w_ctx, entry);

	qblk_update_map_cache(qblk, rb, w_ctx.lba, entry->cacheline);
	flags = w_ctx.flags | QBLK_WRITTEN_DATA;

	/* Release flags on write context. Protect from writes */
	smp_store_release(&entry->w_ctx.flags, flags);
}

static void qblk_rb_write_entry_gc(struct qblk *qblk,
				struct qblk_rb *rb, void *data,
				unsigned long metadata,
			    struct qblk_w_ctx w_ctx, struct qblk_line *line,
			    u64 paddr, unsigned int ring_pos)
{
	struct qblk_rb_entry *entry;
	int flags;

	entry = &rb->entries[ring_pos];
	flags = READ_ONCE(entry->w_ctx.flags);
#ifdef CONFIG_NVM_DEBUG
	/* Caller must guarantee that the entry is free */
	BUG_ON(!(flags & QBLK_WRITABLE_ENTRY));
#endif

	__qblk_rb_write_entry(rb, data, metadata, w_ctx, entry);

	if (!qblk_update_map_gc(qblk, rb, w_ctx.lba, entry->cacheline, line, paddr))
		entry->w_ctx.lba = ADDR_EMPTY;

	flags = w_ctx.flags | QBLK_WRITTEN_DATA;

	/* Release flags on write context. Protect from writes */
	smp_store_release(&entry->w_ctx.flags, flags);
}

void qblk_rb_data_free(struct qblk_rb *rb)
{
	struct qblk_rb_pages *p, *t;

	down_write(&qblk_rb_lock);
	list_for_each_entry_safe(p, t, &rb->pages, list) {
		free_pages((unsigned long)page_address(p->pages), p->order);
		list_del(&p->list);
		kfree(p);
	}
	up_write(&qblk_rb_lock);
}

/*
 * Initialize ring buffer. The data and metadata buffers must be previously
 * allocated and their size must be a power of two
 * (Documentation/circular-buffers.txt)
 */
int qblk_rb_init(struct qblk *qblk, struct qblk_rb *rb,
		unsigned int rbIndex, struct qblk_rb_entry *rb_entry_base,
		unsigned int power_size, unsigned int power_seg_sz)
{
	unsigned int init_entry = 0;
	unsigned int alloc_order = power_size;
	unsigned int max_order = MAX_ORDER - 1;
	unsigned int order, iter;

	//pr_notice("%s, powersize=%u, power_seg_sz=%u\n",
	//			__func__, power_size, power_seg_sz);

	down_write(&qblk_rb_lock);
	rb->rb_index = rbIndex;
	rb->entries = rb_entry_base;
	rb->seg_size = (1 << power_seg_sz);
	rb->nr_entries = (1 << power_size);
	rb->mem = rb->subm = rb->sync = rb->l2p_update = 0;
	atomic_set(&rb->flush_point, EMPTY_ENTRY);

	spin_lock_init(&rb->w_lock);
	spin_lock_init(&rb->s_lock);
	spin_lock_init(&rb->fp_write_lock);

	INIT_LIST_HEAD(&rb->pages);

	if (alloc_order >= max_order) {
		order = max_order;
		iter = (1 << (alloc_order - max_order));
	} else {
		order = alloc_order;
		iter = 1;
	}

	do {
		struct qblk_rb_entry *entry;
		struct qblk_rb_pages *page_set;
		void *kaddr;
		unsigned long set_size;
		int i;

		page_set = kmalloc(sizeof(struct qblk_rb_pages), GFP_KERNEL);
		if (!page_set) {
			up_write(&qblk_rb_lock);
			return -ENOMEM;
		}

		page_set->order = order;
		page_set->pages = alloc_pages(GFP_KERNEL, order);
		if (!page_set->pages) {
			kfree(page_set);
			qblk_rb_data_free(rb);
			up_write(&qblk_rb_lock);
			return -ENOMEM;
		}
		kaddr = page_address(page_set->pages);

		entry = &rb->entries[init_entry];
		entry->data = kaddr;
		entry->cacheline = qblk_cacheline_to_addr(rbIndex, init_entry++);
		entry->w_ctx.flags = QBLK_WRITABLE_ENTRY;
		INIT_LIST_HEAD(&entry->w_ctx.persist_list);
		entry->w_ctx.fua_req = NULL;

		set_size = (1 << order);
		for (i = 1; i < set_size; i++) {
			entry = &rb->entries[init_entry];
			entry->cacheline = qblk_cacheline_to_addr(rbIndex, init_entry++);
			entry->data = kaddr + (i * rb->seg_size);
			entry->w_ctx.flags = QBLK_WRITABLE_ENTRY;
			INIT_LIST_HEAD(&entry->w_ctx.persist_list);
		}

		list_add_tail(&page_set->list, &rb->pages);
		iter--;
	} while (iter > 0);
	up_write(&qblk_rb_lock);

	qblk->total_buf_entries += rb->nr_entries;
	//pr_notice("%s, rb[%u] init finished with %lu entries\n",
	//			__func__, rbIndex, (1UL << order));

	return 0;
}

/*
 * qblk_rb_calculate_size -- calculate the size of the write buffer
 */
unsigned int qblk_rb_calculate_size(unsigned int nr_entries)
{
	/* Alloc a write buffer that can at least fit 128 entries */
	return (1 << max(get_count_order(nr_entries), 7));
}


void *qblk_rb_entries_ref(struct qblk_rb *rb)
{
	return rb->entries;
}

int qblk_rb_tear_down_check(struct qblk_rb *rb)
{
	struct qblk_rb_entry *entry;
	int i;
	int ret = 0;

	spin_lock(&rb->w_lock);
	spin_lock_irq(&rb->s_lock);

	if ((rb->mem == rb->subm) && (rb->subm == rb->sync) &&
				(rb->sync == rb->l2p_update) &&
				(atomic_read(&rb->flush_point) == EMPTY_ENTRY)) {
		goto out;
	}

	if (!rb->entries) {
		ret = 1;
		goto out;
	}

	for (i = 0; i < rb->nr_entries; i++) {
		entry = &rb->entries[i];

		if (!entry->data) {
			ret = 1;
			goto out;
		}
	}

out:
	spin_unlock(&rb->w_lock);
	spin_unlock_irq(&rb->s_lock);

	return ret;
}

int qblk_rb_pos_oob(struct qblk_rb *rb, u64 pos)
{
	return (pos >= rb->nr_entries);
}

void printRbStatus(struct qblk_rb *ringBuffer, unsigned int rbIndex)
{
	int i;

	spin_lock(&ringBuffer->w_lock);
	pr_notice("''''''''''''''%s''''''''''''''\n",	__func__);
	pr_notice("rb[%u] status: flushpoint=%u, l2pupdate=%u, mem=%u,subm=%u,sync=%u\n",
		rbIndex, atomic_read(&ringBuffer->flush_point),
		READ_ONCE(ringBuffer->l2p_update),
		READ_ONCE(ringBuffer->mem),
		READ_ONCE(ringBuffer->subm),
		READ_ONCE(ringBuffer->sync));
	for (i = 0; i < 8; i++) {
		pr_notice("[%d]:cacheline=0x%llx, wctxflags=0x%x, wctxlba=0x%llx, wctxppa=0x%llx\n",
			i,
			ringBuffer->entries[i].cacheline.ppa,
			ringBuffer->entries[i].w_ctx.flags,
			ringBuffer->entries[i].w_ctx.lba,
			ringBuffer->entries[i].w_ctx.ppa.ppa);
	}
	//pr_notice("%s^^^^^^^^^^^^^END^^^^^^^^^^^^^^^^^^^^^\n",
	//													__func__);
	spin_unlock(&ringBuffer->w_lock);
}

blk_status_t qblk_rq_write_to_cache(struct qblk *qblk,
				struct qblk_queue *pq,
				struct request *req,
				unsigned long flags)
{
	struct request_queue *q = req->q;
	struct qblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	int i;
	int ret;
	struct bio *bio, *newbio;
	unsigned int rbIndex = pq->rb_idx;
	struct qblk_rb *ringBuffer = pq->rb;
	unsigned long start_time = jiffies;
	sector_t lba;
	int nr_entries;
	unsigned int qid;
	int max_payload_pgs;
	int endreq = 1;
	int biocount;

	//pr_notice("%s, reqflags=0x%x, cmdflags=0x%x, nrseg=%u, bio=%p\n",
	//		__func__, req->rq_flags, req->cmd_flags,
	//		req->nr_phys_segments, req->bio);

	biocount = 0;
	__rq_for_each_bio(bio, req) {
		lba = qblk_get_lba(bio);
		nr_entries = qblk_get_secs(bio);
		qid = pq->rb_idx;

		WARN_ON(biocount++);
		//bio_get(bio);/////////

		//pr_notice("%s, write bio info, rbIndex=%u, lba=%lu, nrEntries=%d bi_opf=0x%x\n",
		//			__func__,
		//			rbIndex, lba,
		//			nr_entries, bio->bi_opf);

		/* Update the write buffer head (mem) with the entries that we can
		 * write. The write in itself cannot fail, so there is no need to
		 * rollback from here on.
		 */
		ret = qblk_rb_may_write_user(qblk, qid, ringBuffer, bio, nr_entries, &bpos, req);
		switch (ret) {
		case -1:
			endreq = 0;
		case 0:
			break;
		case 1:
			//pr_notice("%s,return with BLK_STS_RESOURCE\n", __func__);
			//printRbStatus(ringBuffer, rbIndex);
			return BLK_STS_RESOURCE;
		case -2:
			/*pblk_pipeline_stop(pblk);*/ //---
			return BLK_STS_IOERR;
		default:
			max_payload_pgs = ret - qblk->min_write_pgs;

			/* We only split bios that exceed ringBuffer's capacity */
			if (nr_entries <= max_payload_pgs)
				return BLK_STS_RESOURCE;

			max_payload_pgs >>= 1;
			newbio = bio_split(bio,
						max_payload_pgs << 3,
						GFP_ATOMIC, &q->bio_split);

			newbio->bi_opf |= REQ_NOMERGE;
			newbio->bi_next = bio->bi_next;
			bio->bi_next = newbio;
			
			return BLK_STS_RESOURCE;
		}
		//printRbStatus(ringBuffer,rbIndex);
		if (unlikely(!bio_has_data(bio)))
			break;

		generic_start_io_acct(q, WRITE, blk_rq_sectors(req), &qblk->disk->part0);

		qblk_ppa_set_empty(&w_ctx.ppa);
		smp_store_release(&w_ctx.flags, flags);

		for (i = 0; i < nr_entries; i++) {
			void *data = bio_data(bio);
			unsigned long *pmetadata = bio_metadata(bio);
			unsigned long metadata = pmetadata?*pmetadata:0;
			//unsigned long metadata = 0;

			w_ctx.lba = lba + i;
			//pr_notice("%s:wctx[%d].lba=0x%llx pmeta=%p meta=%lu\n",
			//	__func__, i, w_ctx.lba, pmetadata, metadata);

			pos = qblk_rb_wrap_pos(ringBuffer, bpos + i);
			qblk_rb_write_entry_user(qblk, ringBuffer, data, metadata, w_ctx, pos);
			//qblk_rb_write_entry_user(qblk, ringBuffer, data, NULL, w_ctx, pos);

			bio_advance(bio, QBLK_EXPOSED_PAGE_SIZE);
		}

/*
#ifdef CONFIG_NVM_DEBUG
		atomic_long_add(nr_entries, &qblk->inflight_writes);
		atomic_long_add(nr_entries, &qblk->req_writes);
#endif
*/

		qblk_rl_inserted(&qblk->rl, nr_entries);
		//break;
	}
	atomic_inc(&qblk->total_submitted);
	if (endreq) {
		generic_end_io_acct(q, WRITE, &qblk->disk->part0, start_time);
		//pr_notice("%s,endrequest with BLK_STS_OK,lba=%lu, nrEntries=%d\n",__func__,lba,nr_entries);
		blk_mq_end_request(req, BLK_STS_OK);
		atomic_inc(&qblk->total_finished);
	}

	qblk_write_should_kick(qblk, rbIndex, (req->cmd_flags & REQ_NOMERGE)?0:1);

	//pr_notice("%s,ret=%d\n", __func__, ret);
	return BLK_STS_OK;
}

/*
 * Blk-mq serializes flush requests on each cpu. But flush requests
 * from different CPUs can be issued concurrently.
 * Since the sematic of flush request requires the driver to persist
 * all data in the volatile buffer, QBLK serializes all flush requests
 * among CPUs.
 */
blk_status_t qblk_flush_req(struct request_queue *q,
						struct qblk *qblk, struct qblk_queue *pq,
						struct request *req)
{
	unsigned int nr_rb = qblk->nr_queues;
	struct qblk_persist_work *persist_work;

	WARN_ON(req->bio);
	//pr_notice("%s, rbindex=%u\n", __func__, pq->rb_idx);

	persist_work = qblk_persist_work_alloc_init(req, nr_rb);
	if (!persist_work)
		return BLK_STS_RESOURCE;

	while (nr_rb--)
		qblk_rb_persist_point_set(qblk, nr_rb, &qblk->mqrwb[nr_rb],
												persist_work);

	qblk_write_force_kick_all(qblk);
	return BLK_STS_OK;
}

unsigned int qblk_rb_wrap_pos(struct qblk_rb *rb, unsigned int pos)
{
	return (pos & (rb->nr_entries - 1));
}

/*
 * Read available entries on rb and add them to the given bio. To avoid a memory
 * copy, a page reference to the write buffer is used to be added to the bio.
 *
 * This function is used by the write thread to form the write bio that will
 * persist data on the write buffer to the media.
 */
unsigned int qblk_rb_read_to_bio(struct qblk *qblk,
				struct qblk_rb *rb, struct nvm_rq *rqd,
				unsigned int pos, unsigned int nr_entries,
				unsigned int count)
{
	struct request_queue *q = qblk->dev->q;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;
	struct qblk_rb_entry *entry;
	struct page *page;
	unsigned int pad = 0, to_read = nr_entries;
	unsigned int i;
	int flags;

	if (count < nr_entries) {
		pad = nr_entries - count;
		to_read = count;
	}

	c_ctx->sentry = pos;
	c_ctx->nr_valid = to_read;
	c_ctx->nr_padded = pad;

	//pr_notice("%s,rb=%lu,pos=%u,nr_entries=%u,count=%u\n", __func__,
	//	((unsigned long)rb - (unsigned long)qblk->mqrwb)/sizeof(struct qblk_rb),
	//	pos,nr_entries,count);

	for (i = 0; i < to_read; i++) {
		entry = &rb->entries[pos];

		/* A write has been allowed into the buffer, but data is still
		 * being copied to it. It is ok to busy wait.
		 */
retry:
		flags = READ_ONCE(entry->w_ctx.flags);
		if (!(flags & QBLK_WRITTEN_DATA)) {
			io_schedule();
			goto retry;
		}

		page = virt_to_page(entry->data);
		if (!page) {
			pr_err("qblk: could not allocate write bio page\n");
			flags &= ~QBLK_WRITTEN_DATA;
			flags |= QBLK_SUBMITTED_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		if (bio_add_pc_page(q, bio, page, rb->seg_size, 0) !=
								rb->seg_size) {
			pr_err("qblk: could not add page to write bio\n");
			flags &= ~QBLK_WRITTEN_DATA;
			flags |= QBLK_SUBMITTED_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		flags &= ~QBLK_WRITTEN_DATA;
		flags |= QBLK_SUBMITTED_ENTRY;

		/* Release flags on context. Protect from writes */
		smp_store_release(&entry->w_ctx.flags, flags);

		pos = (pos + 1) & (rb->nr_entries - 1);
	}

	if (pad) {
		if (qblk_bio_add_pages(qblk, bio, GFP_KERNEL, pad)) {
			pr_err("qblk: could not pad page in write bio\n");
			return NVM_IO_ERR;
		}
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(pad, &qblk->padded_writes);
#endif

	return NVM_IO_OK;
}

/*
 * Look at qblk_rb_may_write_user comment
 */
static int qblk_rb_may_write_gc(struct qblk *qblk,
			struct qblk_rb *rb, struct ch_info *chi,
			unsigned int nr_entries,
			unsigned int *pos)
{
	
	if (qblk_rl_gc_maynot_insert(&qblk->rl, &chi->per_ch_rl, nr_entries))
		return 0;

	spin_lock(&rb->w_lock);
	if (!qblk_rb_may_write(qblk, rb, nr_entries, pos)) {
		spin_unlock(&rb->w_lock);
		return 0;
	}

	qblk_rl_gc_in(&qblk->rl, nr_entries);
	spin_unlock(&rb->w_lock);

	return 1;
}

/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int qblk_write_gc_to_cache(struct qblk *qblk, struct qblk_gc_rq *gc_rq)
{
	struct qblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	void *data = gc_rq->data;
	struct qblk_sec_meta *metadata = gc_rq->meta;
	int i, valid_entries;
	int cpuid;
	struct qblk_rb *rb = NULL, *last_rb = NULL;
	struct ch_info *chi = gc_rq->chi;

	for (i = 0, valid_entries = 0; i < gc_rq->nr_secs; i++) {
		if (gc_rq->lba_list[i] == ADDR_EMPTY)
			continue;
retry:
		cpuid = get_cpu();
		rb = &qblk->mqrwb[cpuid];

		if (!qblk_rb_may_write_gc(qblk, rb, chi, 1, &bpos)) {
			put_cpu();
			io_schedule();
			goto retry;
		}
		smp_store_release(&w_ctx.flags, QBLK_IOTYPE_GC);
		qblk_ppa_set_empty(&w_ctx.ppa);
		w_ctx.lba = gc_rq->lba_list[i];
		pos = qblk_rb_wrap_pos(rb, bpos);
		qblk_rb_write_entry_gc(qblk, rb, data,
						metadata[i].reserved,
						w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], pos);
		
		data += QBLK_EXPOSED_PAGE_SIZE;
		valid_entries++;
		put_cpu();

		if (rb != last_rb) {
			if (last_rb)
				qblk_write_should_kick(qblk, last_rb->rb_index, 0);
			last_rb = rb;
		}
	}

	WARN_ONCE(gc_rq->secs_to_gc != valid_entries,
					"qblk: inconsistent GC write\n");
					
#ifdef CONFIG_NVM_DEBUG
	/* FIXME: Seems like these debugging variables are corrupted. */
	atomic_long_add(valid_entries, &qblk->inflight_writes);
	atomic_long_add(valid_entries, &qblk->recov_gc_writes);
#endif

	if (likely(last_rb))
		qblk_write_should_kick(qblk, last_rb->rb_index, 0);
					
	return NVM_IO_OK;

}

