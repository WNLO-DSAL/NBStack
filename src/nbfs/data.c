// SPDX-License-Identifier: GPL-2.0
/*
 * fs/nbfs/data.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/nbfs_fs.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/prefetch.h>
#include <linux/uio.h>
#include <linux/cleancache.h>
#include <linux/sched/signal.h>

#include "nbfs.h"
#include "node.h"
#include "segment.h"
#include "trace.h"
#include <trace/events/nbfs.h>

#define NUM_PREALLOC_POST_READ_CTXS	128

static struct kmem_cache *bio_post_read_ctx_cache;
static mempool_t *bio_post_read_ctx_pool;
static struct kmem_cache *bio_write_node_info;
static struct kmem_cache *bio_write_node_entries;

static bool __is_cp_guaranteed(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode;
	struct nbfs_sb_info *sbi;

	if (!mapping)
		return false;

	inode = mapping->host;
	sbi = NBFS_I_SB(inode);

	if (inode->i_ino == NBFS_META_INO(sbi) ||
			inode->i_ino ==  NBFS_NODE_INO(sbi) ||
			S_ISDIR(inode->i_mode) ||
			(S_ISREG(inode->i_mode) &&
			(nbfs_is_atomic_file(inode) || IS_NOQUOTA(inode))) ||
			is_cold_data(page))
		return true;
	return false;
}

static enum count_type __read_io_type(struct page *page)
{
	struct address_space *mapping = page->mapping;

	if (mapping) {
		struct inode *inode = mapping->host;
		struct nbfs_sb_info *sbi = NBFS_I_SB(inode);

		if (inode->i_ino == NBFS_META_INO(sbi))
			return NBFS_RD_META;

		if (inode->i_ino == NBFS_NODE_INO(sbi))
			return NBFS_RD_NODE;
	}
	return NBFS_RD_DATA;
}

/* postprocessing steps for read bios */
enum bio_post_read_step {
	STEP_INITIAL = 0,
	STEP_DECRYPT,
};

struct bio_post_read_ctx {
	struct bio *bio;
	struct work_struct work;
	unsigned int cur_step;
	unsigned int enabled_steps;
};

static void __read_end_io(struct bio *bio)
{
	struct page *page;
	struct bio_vec *bv;
	int i;
	struct bvec_iter_all iter_all;

	bio_for_each_segment_all(bv, bio, i, iter_all) {
		page = bv->bv_page;

		/* PG_error was set if any post_read step failed */
		if (bio->bi_status || PageError(page)) {
			ClearPageUptodate(page);
			/* will re-read again later */
			ClearPageError(page);
		} else {
			SetPageUptodate(page);
		}
		dec_page_count(NBFS_P_SB(page), __read_io_type(page));
		unlock_page(page);
	}
	if (bio->bi_private)
		mempool_free(bio->bi_private, bio_post_read_ctx_pool);
	bio_put(bio);
}

static void bio_post_read_processing(struct bio_post_read_ctx *ctx);

static void decrypt_work(struct work_struct *work)
{
	struct bio_post_read_ctx *ctx =
		container_of(work, struct bio_post_read_ctx, work);

	fscrypt_decrypt_bio(ctx->bio);

	bio_post_read_processing(ctx);
}

static void bio_post_read_processing(struct bio_post_read_ctx *ctx)
{
	switch (++ctx->cur_step) {
	case STEP_DECRYPT:
		if (ctx->enabled_steps & (1 << STEP_DECRYPT)) {
			INIT_WORK(&ctx->work, decrypt_work);
			fscrypt_enqueue_decrypt_work(&ctx->work);
			return;
		}
		ctx->cur_step++;
		/* fall-through */
	default:
		__read_end_io(ctx->bio);
	}
}

static bool nbfs_bio_post_read_required(struct bio *bio)
{
	return bio->bi_private && !bio->bi_status;
}

static void nbfs_read_end_io(struct bio *bio)
{
	if (time_to_inject(NBFS_P_SB(bio_first_page_all(bio)),
						FAULT_READ_IO)) {
		nbfs_show_injection_info(FAULT_READ_IO);
		bio->bi_status = BLK_STS_IOERR;
	}

	if (nbfs_bio_post_read_required(bio)) {
		struct bio_post_read_ctx *ctx = bio->bi_private;

		ctx->cur_step = STEP_INITIAL;
		bio_post_read_processing(ctx);
		return;
	}

	__read_end_io(bio);
}

static void nbfs_write_end_io(struct bio *bio)
{
	struct nbfs_sb_info *sbi = bio->bi_private;
	struct bio_vec *bvec;
	int i;
	struct bvec_iter_all iter_all;

	if (time_to_inject(sbi, FAULT_WRITE_IO)) {
		nbfs_show_injection_info(FAULT_WRITE_IO);
		bio->bi_status = BLK_STS_IOERR;
	}

	bio_for_each_segment_all(bvec, bio, i, iter_all) {
		struct page *page = bvec->bv_page;
		enum count_type type = WB_DATA_TYPE(page);

		if (IS_DUMMY_WRITTEN_PAGE(page)) {
			set_page_private(page, (unsigned long)NULL);
			ClearPagePrivate(page);
			unlock_page(page);
			mempool_free(page, sbi->write_io_dummy);

			if (unlikely(bio->bi_status))
				nbfs_stop_checkpoint(sbi, true);
			continue;
		}

		fscrypt_pullback_bio_page(&page, true);

		if (unlikely(bio->bi_status)) {
			mapping_set_error(page->mapping, -EIO);
			if (type == NBFS_WB_CP_DATA)
				nbfs_stop_checkpoint(sbi, true);
		}

		nbfs_bug_on(sbi, page->mapping == NODE_MAPPING(sbi) &&
					page->index != nid_of_node(page));

		dec_page_count(sbi, type);
		if (nbfs_in_warm_node_list(sbi, page))
			nbfs_del_fsync_node_entry(sbi, page);
		clear_cold_data(page);
		end_page_writeback(page);
	}
	if (!get_pages(sbi, NBFS_WB_CP_DATA) &&
				wq_has_sleeper(&sbi->cp_wait))
		wake_up(&sbi->cp_wait);

	bio_put(bio);
}

#ifdef USE_NBFS
static void nbfs_read_end_io_withoob(struct bio *bio)
{
	if (time_to_inject(NBFS_P_SB(bio_first_page_all(bio)),
						FAULT_READ_IO)) {
		nbfs_show_injection_info(FAULT_READ_IO);
		bio->bi_status = BLK_STS_IOERR;
	}

	if (nbfs_bio_post_read_required(bio)) {
		struct bio_post_read_ctx *ctx = bio->bi_private;

		ctx->cur_step = STEP_INITIAL;
		bio_post_read_processing(ctx);
		return;
	}

	__read_end_io(bio);
}

static void nbfs_write_end_io_withoob(struct bio *bio)
{
	struct bio_wn_info_header *wni = bio->bi_private;
	struct nbfs_sb_info *sbi = wni->sbi;
	struct bio_vec *bvec;
	int i;
	struct bvec_iter_all iter_all;
	unsigned long **ppmeta;

	if (time_to_inject(sbi, FAULT_WRITE_IO)) {
		nbfs_show_injection_info(FAULT_WRITE_IO);
		bio->bi_status = BLK_STS_IOERR;
	}

	bio_for_each_segment_all(bvec, bio, i, iter_all) {
		struct page *page = bvec->bv_page;
		enum count_type type = WB_DATA_TYPE(page);

		if (IS_DUMMY_WRITTEN_PAGE(page)) {
			set_page_private(page, (unsigned long)NULL);
			ClearPagePrivate(page);
			unlock_page(page);
			mempool_free(page, sbi->write_io_dummy);

			if (unlikely(bio->bi_status))
				nbfs_stop_checkpoint(sbi, true);
			continue;
		}

		fscrypt_pullback_bio_page(&page, true);

		if (unlikely(bio->bi_status)) {
			mapping_set_error(page->mapping, -EIO);
			if (type == NBFS_WB_CP_DATA)
				nbfs_stop_checkpoint(sbi, true);
		}

		nbfs_bug_on(sbi, page->mapping == NODE_MAPPING(sbi) &&
					page->index != nid_of_node(page));

		dec_page_count(sbi, type);
		if (nbfs_in_warm_node_list(sbi, page)) {
			struct bio_wn_info_entry *wn_entry, *next;

			list_for_each_entry_safe(wn_entry, next, &wni->inode_list, inode_list) {
				if (wn_entry->page == page) {
					list_del(&wn_entry->inode_list);
					nbfs_del_wb_node_entry(wn_entry->inode, page);
					iput(wn_entry->inode);
					kmem_cache_free(bio_write_node_entries, wn_entry);
					goto this_one_ok;
				}
			}
			pr_err("%s, entry not found\n", __func__);
			dump_stack();
		}
this_one_ok:
		clear_cold_data(page);
		end_page_writeback(page);
	}
	if (!get_pages(sbi, NBFS_WB_CP_DATA) &&
				wq_has_sleeper(&sbi->cp_wait))
		wake_up(&sbi->cp_wait);

	if (bio_has_metadata(bio)) {
		unsigned int iter;

		for (ppmeta = bio->bi_meta.bi_metabase,
				iter = 0;
				iter < bio->bi_meta.bi_metafilled;
				iter++,
				ppmeta++)
		{
			if (*ppmeta)
				nbfs_free_extradata(*ppmeta);
		}
	}

	kmem_cache_free(bio_write_node_info, wni);
	bio_put(bio);
}

/* See comments above do_write_page_withoob() */
static void nbfs_write_end_io_withoob_forceCP(struct bio *bio)
{
	struct bio_wn_info_header *wni = bio->bi_private;
	struct nbfs_sb_info *sbi = wni->sbi;
	struct bio_vec *bvec;
	int i;
	struct bvec_iter_all iter_all;
	unsigned long **ppmeta;

	if (time_to_inject(sbi, FAULT_WRITE_IO)) {
		nbfs_show_injection_info(FAULT_WRITE_IO);
		bio->bi_status = BLK_STS_IOERR;
	}

	bio_for_each_segment_all(bvec, bio, i, iter_all) {
		struct page *page = bvec->bv_page;
		enum count_type type = NBFS_WB_CP_DATA;

		if (IS_DUMMY_WRITTEN_PAGE(page)) {
			set_page_private(page, (unsigned long)NULL);
			ClearPagePrivate(page);
			unlock_page(page);
			mempool_free(page, sbi->write_io_dummy);

			if (unlikely(bio->bi_status))
				nbfs_stop_checkpoint(sbi, true);
			continue;
		}

		fscrypt_pullback_bio_page(&page, true);

		if (unlikely(bio->bi_status)) {
			mapping_set_error(page->mapping, -EIO);
			if (type == NBFS_WB_CP_DATA)
				nbfs_stop_checkpoint(sbi, true);
		}

		nbfs_bug_on(sbi, page->mapping == NODE_MAPPING(sbi) &&
					page->index != nid_of_node(page));

		dec_page_count(sbi, type);
		if (nbfs_in_warm_node_list(sbi, page)) {
			struct bio_wn_info_entry *wn_entry, *next;

			list_for_each_entry_safe(wn_entry, next, &wni->inode_list, inode_list) {
				if (wn_entry->page == page) {
					list_del(&wn_entry->inode_list);
					nbfs_del_wb_node_entry(wn_entry->inode, page);
					iput(wn_entry->inode);
					kmem_cache_free(bio_write_node_entries, wn_entry);
					goto this_one_ok;
				}
			}
			pr_err("%s, entry not found\n", __func__);
			dump_stack();
		}
this_one_ok:
		clear_cold_data(page);
		end_page_writeback(page);
	}
	if (!get_pages(sbi, NBFS_WB_CP_DATA) &&
				wq_has_sleeper(&sbi->cp_wait))
		wake_up(&sbi->cp_wait);

	if (bio_has_metadata(bio)) {
		unsigned int iter;

		for (ppmeta = bio->bi_meta.bi_metabase,
				iter = 0;
				iter < bio->bi_meta.bi_metafilled;
				iter++,
				ppmeta++)
		{
			if (*ppmeta)
				nbfs_free_extradata(*ppmeta);
		}
	}

	kmem_cache_free(bio_write_node_info, wni);
	bio_put(bio);
}

#endif

/*
 * Return true, if pre_bio's bdev is same as its target device.
 */
struct block_device *nbfs_target_device(struct nbfs_sb_info *sbi,
				block_t blk_addr, struct bio *bio)
{
	struct block_device *bdev = sbi->sb->s_bdev;
	int i;

	for (i = 0; i < sbi->s_ndevs; i++) {
		if (FDEV(i).start_blk <= blk_addr &&
					FDEV(i).end_blk >= blk_addr) {
			blk_addr -= FDEV(i).start_blk;
			bdev = FDEV(i).bdev;
			break;
		}
	}
	if (bio) {
		bio_set_dev(bio, bdev);
		bio->bi_iter.bi_sector = SECTOR_FROM_BLOCK(blk_addr);
	}
	return bdev;
}

int nbfs_target_device_index(struct nbfs_sb_info *sbi, block_t blkaddr)
{
	int i;

	for (i = 0; i < sbi->s_ndevs; i++)
		if (FDEV(i).start_blk <= blkaddr && FDEV(i).end_blk >= blkaddr)
			return i;
	return 0;
}

static bool __same_bdev(struct nbfs_sb_info *sbi,
				block_t blk_addr, struct bio *bio)
{
	struct block_device *b = nbfs_target_device(sbi, blk_addr, NULL);
	return bio->bi_disk == b->bd_disk && bio->bi_partno == b->bd_partno;
}

/*
 * Low-level block read/write IO operations.
 */
static struct bio *__bio_alloc(struct nbfs_sb_info *sbi, block_t blk_addr,
				struct writeback_control *wbc,
				int npages, bool is_read,
				enum page_type type, enum temp_type temp)
{
	struct bio *bio;

	bio = nbfs_bio_alloc(sbi, npages, true);

	nbfs_target_device(sbi, blk_addr, bio);
	if (is_read) {
		bio->bi_end_io = nbfs_read_end_io;
		bio->bi_private = NULL;
	} else {
		bio->bi_end_io = nbfs_write_end_io;
		bio->bi_private = sbi;
		bio->bi_write_hint = nbfs_io_type_to_rw_hint(sbi, type, temp);
	}
	if (wbc)
		wbc_init_bio(wbc, bio);

	return bio;
}

#ifdef USE_NBFS
static struct bio *__bio_alloc_withoob(struct nbfs_sb_info *sbi, block_t blk_addr,
				struct writeback_control *wbc,
				int npages, bool is_read,
				enum page_type type, enum temp_type temp, bool forceCP)
{
	struct bio *bio;

	bio = nbfs_bio_alloc_withoob(sbi, npages, true);

	nbfs_target_device(sbi, blk_addr, bio);
	if (is_read) {
		bio->bi_end_io = nbfs_read_end_io_withoob;
		bio->bi_private = NULL;
	} else {
		struct bio_wn_info_header *wni;

		if (forceCP)
			bio->bi_end_io = nbfs_write_end_io_withoob_forceCP;
		else
			bio->bi_end_io = nbfs_write_end_io_withoob;
		wni = nbfs_kmem_cache_alloc(bio_write_node_info, GFP_NOFS);
		wni->sbi = sbi;
		INIT_LIST_HEAD(&wni->inode_list);
		bio->bi_private = wni;
		bio->bi_write_hint = nbfs_io_type_to_rw_hint(sbi, type, temp);
	}
	if (wbc)
		wbc_init_bio(wbc, bio);

	return bio;
}
#endif

static inline void __submit_bio(struct nbfs_sb_info *sbi,
				struct bio *bio, enum page_type type)
{
	if (!is_read_io(bio_op(bio))) {
		unsigned int start;

		if (type != DATA && type != NODE)
			goto submit_io;

		if (test_opt(sbi, LFS) && current->plug)
			blk_finish_plug(current->plug);

		start = bio->bi_iter.bi_size >> NBFS_BLKSIZE_BITS;
		start %= NBFS_IO_SIZE(sbi);

		if (start == 0)
			goto submit_io;

		/* fill dummy pages */
		for (; start < NBFS_IO_SIZE(sbi); start++) {
			struct page *page =
				mempool_alloc(sbi->write_io_dummy,
					      GFP_NOIO | __GFP_NOFAIL);
			nbfs_bug_on(sbi, !page);

			zero_user_segment(page, 0, PAGE_SIZE);
			SetPagePrivate(page);
			set_page_private(page, (unsigned long)DUMMY_WRITTEN_PAGE);
			lock_page(page);
			if (bio_add_page(bio, page, PAGE_SIZE, 0) < PAGE_SIZE)
				nbfs_bug_on(sbi, 1);
		}
		/*
		 * In the NODE case, we lose next block address chain. So, we
		 * need to do checkpoint in nbfs_sync_file.
		 */
		if (type == NODE)
			set_sbi_flag(sbi, SBI_NEED_CP);
	}
submit_io:
	if (is_read_io(bio_op(bio)))
		trace_nbfs_submit_read_bio(sbi->sb, type, bio);
	else
		trace_nbfs_submit_write_bio(sbi->sb, type, bio);
	//print bio status
	//nbfs_printBioStatus(bio);
	submit_bio(bio);
}

static void __submit_merged_bio(struct nbfs_bio_info *io)
{
	struct nbfs_io_info *fio = &io->fio;

	if (!io->bio)
		return;

	bio_set_op_attrs(io->bio, fio->op, fio->op_flags);

	if (is_read_io(fio->op))
		trace_nbfs_prepare_read_bio(io->sbi->sb, fio->type, io->bio);
	else
		trace_nbfs_prepare_write_bio(io->sbi->sb, fio->type, io->bio);

	__submit_bio(io->sbi, io->bio, fio->type);
	io->bio = NULL;
}

static bool __has_merged_page(struct nbfs_bio_info *io, struct inode *inode,
						struct page *page, nid_t ino)
{
	struct bio_vec *bvec;
	struct page *target;
	int i;
	struct bvec_iter_all iter_all;

	if (!io->bio)
		return false;

	if (!inode && !page && !ino)
		return true;

	bio_for_each_segment_all(bvec, io->bio, i, iter_all) {

		if (bvec->bv_page->mapping)
			target = bvec->bv_page;
		else
			target = fscrypt_control_page(bvec->bv_page);

		if (inode && inode == target->mapping->host)
			return true;
		if (page && page == target)
			return true;
		if (ino && ino == ino_of_node(target))
			return true;
	}

	return false;
}

static void __nbfs_submit_merged_write(struct nbfs_sb_info *sbi,
				enum page_type type, enum temp_type temp, bool preflush)
{
	enum page_type btype = PAGE_TYPE_OF_BIO(type);
	struct nbfs_bio_info *io = sbi->write_io[btype] + temp;
	int preflushflag = preflush?REQ_PREFLUSH:0;

	down_write(&io->io_rwsem);
	//pr_notice("%s, fioflag=0x%x, preflush=%d\n", __func__, io->fio.op_flags,preflush);

	/* change META to META_FLUSH in the checkpoint procedure */
	if (type >= META_FLUSH) {
		io->fio.type = META_FLUSH;
		io->fio.op = REQ_OP_WRITE;
		io->fio.op_flags = REQ_META | REQ_PRIO | REQ_SYNC;
		if (!test_opt(sbi, NOBARRIER))
			io->fio.op_flags |= preflushflag | REQ_FUA;
	}
	//pr_notice("%s, fioflag=0x%x\n", __func__, io->fio.op_flags);
	__submit_merged_bio(io);
	up_write(&io->io_rwsem);
}

static void __submit_merged_write_cond(struct nbfs_sb_info *sbi,
				struct inode *inode, struct page *page,
				nid_t ino, enum page_type type, bool force, bool preflush)
{
	enum temp_type temp;
	bool ret = true;

	for (temp = HOT; temp < NR_TEMP_TYPE; temp++) {
		if (!force)	{
			enum page_type btype = PAGE_TYPE_OF_BIO(type);
			struct nbfs_bio_info *io = sbi->write_io[btype] + temp;

			down_read(&io->io_rwsem);
			ret = __has_merged_page(io, inode, page, ino);
			up_read(&io->io_rwsem);
		}
		if (ret)
			__nbfs_submit_merged_write(sbi, type, temp, preflush);

		/* TODO: use HOT temp only for meta pages now. */
		if (type >= META)
			break;
	}
}

void nbfs_submit_merged_write(struct nbfs_sb_info *sbi, enum page_type type)
{
	__submit_merged_write_cond(sbi, NULL, 0, 0, type, true, true);
}

#ifdef USE_NBFS
void nbfs_submit_merged_write_cond_nopreflush(struct nbfs_sb_info *sbi,
				struct inode *inode, struct page *page,
				nid_t ino, enum page_type type)
{
	__submit_merged_write_cond(sbi, inode, page, ino, type, false, false);
}
#endif

void nbfs_submit_merged_write_cond(struct nbfs_sb_info *sbi,
				struct inode *inode, struct page *page,
				nid_t ino, enum page_type type)
{
	__submit_merged_write_cond(sbi, inode, page, ino, type, false, true);
}

void nbfs_flush_merged_writes(struct nbfs_sb_info *sbi)
{
	nbfs_submit_merged_write(sbi, DATA);
	nbfs_submit_merged_write(sbi, NODE);
	nbfs_submit_merged_write(sbi, META);
}

#ifdef USE_NBFS
int nbfs_submit_page_bio_withoob(struct nbfs_io_info *fio)
{
	struct bio *bio;
	struct page *page = fio->encrypted_page ?
			fio->encrypted_page : fio->page;

	if (!nbfs_is_valid_blkaddr(fio->sbi, fio->new_blkaddr,
			__is_meta_io(fio) ? META_GENERIC : DATA_GENERIC))
		return -EFAULT;

	trace_nbfs_submit_page_bio(page, fio);
	nbfs_trace_ios(fio, 0);

	/* Allocate a new bio */
	bio = __bio_alloc_withoob(fio->sbi, fio->new_blkaddr, fio->io_wbc,
				1, is_read_io(fio->op), fio->type, fio->temp, fio->force_cp);

	if (bio_add_page_with_meta(bio, page, PAGE_SIZE,
			0, fio->oobinfo) < PAGE_SIZE) {
		bio_put(bio);
		return -EFAULT;
	}

	if (fio->io_wbc && !is_read_io(fio->op))
		wbc_account_io(fio->io_wbc, page, PAGE_SIZE);

	bio_set_op_attrs(bio, fio->op, fio->op_flags);

	inc_page_count(fio->sbi, is_read_io(fio->op) ?
			__read_io_type(page): WB_DATA_TYPE(fio->page));

	__submit_bio(fio->sbi, bio, fio->type);
	return 0;
}
#endif

/*
 * Fill the locked page with data located in the block address.
 * A caller needs to unlock the page on failure.
 */
int nbfs_submit_page_bio(struct nbfs_io_info *fio)
{
	struct bio *bio;
	struct page *page = fio->encrypted_page ?
			fio->encrypted_page : fio->page;

	if (!nbfs_is_valid_blkaddr(fio->sbi, fio->new_blkaddr,
			__is_meta_io(fio) ? META_GENERIC : DATA_GENERIC))
		return -EFAULT;

	trace_nbfs_submit_page_bio(page, fio);
	nbfs_trace_ios(fio, 0);

	/* Allocate a new bio */
	bio = __bio_alloc(fio->sbi, fio->new_blkaddr, fio->io_wbc,
				1, is_read_io(fio->op), fio->type, fio->temp);

	if (bio_add_page(bio, page, PAGE_SIZE, 0) < PAGE_SIZE) {
		bio_put(bio);
		return -EFAULT;
	}

	if (fio->io_wbc && !is_read_io(fio->op))
		wbc_account_io(fio->io_wbc, page, PAGE_SIZE);

	bio_set_op_attrs(bio, fio->op, fio->op_flags);

	inc_page_count(fio->sbi, is_read_io(fio->op) ?
			__read_io_type(page): WB_DATA_TYPE(fio->page));

	__submit_bio(fio->sbi, bio, fio->type);
	return 0;
}

void nbfs_submit_page_write(struct nbfs_io_info *fio)
{
	struct nbfs_sb_info *sbi = fio->sbi;
	enum page_type btype = PAGE_TYPE_OF_BIO(fio->type);
	struct nbfs_bio_info *io = sbi->write_io[btype] + fio->temp;
	struct page *bio_page;

	nbfs_bug_on(sbi, is_read_io(fio->op));

	down_write(&io->io_rwsem);
next:
	if (fio->in_list) {
		spin_lock(&io->io_lock);
		if (list_empty(&io->io_list)) {
			spin_unlock(&io->io_lock);
			goto out;
		}
		fio = list_first_entry(&io->io_list,
						struct nbfs_io_info, list);
		list_del(&fio->list);
		spin_unlock(&io->io_lock);
	}

#ifdef USE_NBFS
	/* It is possible that we get an fio with/without OOB here. We should distinguish
	 * the way to issue fio with/without OOB.
	 */
	if (likely(fio->oobinfo)) {
		/* Issue with oob. */
		if (__is_valid_data_blkaddr(fio->old_blkaddr))
			verify_block_addr(fio, fio->old_blkaddr);
		verify_block_addr(fio, fio->new_blkaddr);

		bio_page = fio->encrypted_page ? fio->encrypted_page : fio->page;

		/* set submitted = true as a return value */
		fio->submitted = true;

		inc_page_count(sbi, WB_DATA_TYPE(bio_page));

		if (io->bio && (io->last_block_in_bio != fio->new_blkaddr - 1 ||
		    (io->fio.op != fio->op || io->fio.op_flags != fio->op_flags) ||
				!__same_bdev(sbi, fio->new_blkaddr, io->bio)))
			__submit_merged_bio(io);
alloc_new_withoob:
		if (io->bio == NULL) {
			if ((fio->type == DATA || fio->type == NODE) &&
					fio->new_blkaddr & NBFS_IO_SIZE_MASK(sbi)) {
				dec_page_count(sbi, WB_DATA_TYPE(bio_page));
				fio->retry = true;
				goto skip;
			}
			io->bio = __bio_alloc_withoob(sbi, fio->new_blkaddr, fio->io_wbc,
							BIO_MAX_PAGES, false,
							fio->type, fio->temp, fio->force_cp);
			io->fio = *fio;
		}

		if (!bio_has_metadata(io->bio)) {
			__submit_merged_bio(io);
			goto alloc_new_withoob;
		}

		if (bio_add_page_with_meta(io->bio, bio_page, PAGE_SIZE, 0, fio->oobinfo) < PAGE_SIZE) {
			__submit_merged_bio(io);
			goto alloc_new_withoob;
		}

		/* If we need to add the page to the per_inode writeback node list (fi->wb_node_list),
		 * which is done in __write_node_page_withoob(), we need to get a reference to the
		 * inode and record the inode into the bio. By doing so, when this bio ends, we can
		 * remove the entry in the irq.
		 */
		if (nbfs_in_warm_node_list(sbi, bio_page)) {
			struct bio_wn_info_header *wni = io->bio->bi_private;
			struct bio_wn_info_entry *wn_entry =
				nbfs_kmem_cache_alloc(bio_write_node_entries, GFP_NOFS);

			wn_entry->page = bio_page;
			wn_entry->inode = nbfs_iget(sbi->sb, ino_of_node(bio_page));
			INIT_LIST_HEAD(&wn_entry->inode_list);
			//pr_notice("%s ino=%lu, page=%p\n", __func__,
			//					wn_entry->inode->i_ino, bio_page);
			list_add_tail(&wn_entry->inode_list, &wni->inode_list);
		}
	} else {
#endif
		/* Issue without oob. */
		if (__is_valid_data_blkaddr(fio->old_blkaddr))
			verify_block_addr(fio, fio->old_blkaddr);
		verify_block_addr(fio, fio->new_blkaddr);

		bio_page = fio->encrypted_page ? fio->encrypted_page : fio->page;

		/* set submitted = true as a return value */
		fio->submitted = true;

		inc_page_count(sbi, WB_DATA_TYPE(bio_page));

		if (io->bio && (io->last_block_in_bio != fio->new_blkaddr - 1 ||
		    (io->fio.op != fio->op || io->fio.op_flags != fio->op_flags) ||
				!__same_bdev(sbi, fio->new_blkaddr, io->bio)))
			__submit_merged_bio(io);
alloc_new_withoutoob:
		if (io->bio == NULL) {
			if ((fio->type == DATA || fio->type == NODE) &&
					fio->new_blkaddr & NBFS_IO_SIZE_MASK(sbi)) {
				dec_page_count(sbi, WB_DATA_TYPE(bio_page));
				fio->retry = true;
				goto skip;
			}
			io->bio = __bio_alloc(sbi, fio->new_blkaddr, fio->io_wbc,
							BIO_MAX_PAGES, false,
							fio->type, fio->temp);
			io->fio = *fio;
		}

		if (bio_has_metadata(io->bio)) {
			__submit_merged_bio(io);
			goto alloc_new_withoutoob;
		}

		if (bio_add_page(io->bio, bio_page, PAGE_SIZE, 0) < PAGE_SIZE) {
			__submit_merged_bio(io);
			goto alloc_new_withoutoob;
		}
#ifdef USE_NBFS
	}
#endif

	if (fio->io_wbc)
		wbc_account_io(fio->io_wbc, bio_page, PAGE_SIZE);

	io->last_block_in_bio = fio->new_blkaddr;
	nbfs_trace_ios(fio, 0);

	trace_nbfs_submit_page_write(fio->page, fio);
skip:
	if (fio->in_list)
		goto next;
out:
	if (is_sbi_flag_set(sbi, SBI_IS_SHUTDOWN) ||
				nbfs_is_checkpoint_ready(sbi))
		__submit_merged_bio(io);
	up_write(&io->io_rwsem);
}

static struct bio *nbfs_grab_read_bio(struct inode *inode, block_t blkaddr,
					unsigned nr_pages, unsigned op_flag)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	struct bio *bio;
	struct bio_post_read_ctx *ctx;
	unsigned int post_read_steps = 0;

	if (!nbfs_is_valid_blkaddr(sbi, blkaddr, DATA_GENERIC))
		return ERR_PTR(-EFAULT);

	bio = nbfs_bio_alloc(sbi, min_t(int, nr_pages, BIO_MAX_PAGES), false);
	if (!bio)
		return ERR_PTR(-ENOMEM);
	nbfs_target_device(sbi, blkaddr, bio);
	bio->bi_end_io = nbfs_read_end_io;
	bio_set_op_attrs(bio, REQ_OP_READ, op_flag);

	if (nbfs_encrypted_file(inode))
		post_read_steps |= 1 << STEP_DECRYPT;
	if (post_read_steps) {
		ctx = mempool_alloc(bio_post_read_ctx_pool, GFP_NOFS);
		if (!ctx) {
			bio_put(bio);
			return ERR_PTR(-ENOMEM);
		}
		ctx->bio = bio;
		ctx->enabled_steps = post_read_steps;
		bio->bi_private = ctx;
	}

	return bio;
}

/* This can handle encryption stuffs */
static int nbfs_submit_page_read(struct inode *inode, struct page *page,
							block_t blkaddr)
{
	struct bio *bio = nbfs_grab_read_bio(inode, blkaddr, 1, 0);

	if (IS_ERR(bio))
		return PTR_ERR(bio);

	/* wait for GCed page writeback via META_MAPPING */
	nbfs_wait_on_block_writeback(inode, blkaddr);

	if (bio_add_page(bio, page, PAGE_SIZE, 0) < PAGE_SIZE) {
		bio_put(bio);
		return -EFAULT;
	}
	ClearPageError(page);
	inc_page_count(NBFS_I_SB(inode), NBFS_RD_DATA);
	__submit_bio(NBFS_I_SB(inode), bio, DATA);
	return 0;
}

static void __set_data_blkaddr(struct dnode_of_data *dn)
{
	struct nbfs_node *rn = NBFS_NODE(dn->node_page);
	__le32 *addr_array;
	int base = 0;

	if (IS_INODE(dn->node_page) && nbfs_has_extra_attr(dn->inode))
		base = get_extra_isize(dn->inode);

	/* Get physical address of data block */
	addr_array = blkaddr_in_node(rn);
	addr_array[base + dn->ofs_in_node] = cpu_to_le32(dn->data_blkaddr);
}

/*
 * Lock ordering for the change of data block address:
 * ->data_page
 *  ->node_page
 *    update block addresses in the node page
 */
void nbfs_set_data_blkaddr(struct dnode_of_data *dn)
{
	nbfs_wait_on_page_writeback(dn->node_page, NODE, true, true);
	__set_data_blkaddr(dn);
	if (set_page_dirty(dn->node_page))
		dn->node_changed = true;
}

void nbfs_update_data_blkaddr(struct dnode_of_data *dn, block_t blkaddr)
{
	dn->data_blkaddr = blkaddr;
	nbfs_set_data_blkaddr(dn);
	nbfs_update_extent_cache(dn);
}

/* dn->ofs_in_node will be returned with up-to-date last block pointer */
int nbfs_reserve_new_blocks(struct dnode_of_data *dn, blkcnt_t count)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dn->inode);
	int err;

	if (!count)
		return 0;

	if (unlikely(is_inode_flag_set(dn->inode, FI_NO_ALLOC)))
		return -EPERM;
	if (unlikely((err = inc_valid_block_count(sbi, dn->inode, &count))))
		return err;

	trace_nbfs_reserve_new_blocks(dn->inode, dn->nid,
						dn->ofs_in_node, count);

	nbfs_wait_on_page_writeback(dn->node_page, NODE, true, true);

	for (; count > 0; dn->ofs_in_node++) {
		block_t blkaddr = datablock_addr(dn->inode,
					dn->node_page, dn->ofs_in_node);
		if (blkaddr == NULL_ADDR) {
			dn->data_blkaddr = NEW_ADDR;
			__set_data_blkaddr(dn);
			count--;
		}
	}

	if (set_page_dirty(dn->node_page))
		dn->node_changed = true;
	return 0;
}

/* Should keep dn->ofs_in_node unchanged */
int nbfs_reserve_new_block(struct dnode_of_data *dn)
{
	unsigned int ofs_in_node = dn->ofs_in_node;
	int ret;

	ret = nbfs_reserve_new_blocks(dn, 1);
	dn->ofs_in_node = ofs_in_node;
	return ret;
}

int nbfs_reserve_block(struct dnode_of_data *dn, pgoff_t index)
{
	bool need_put = dn->inode_page ? false : true;
	int err;

	err = nbfs_get_dnode_of_data(dn, index, ALLOC_NODE);
	if (err)
		return err;

	if (dn->data_blkaddr == NULL_ADDR)
		err = nbfs_reserve_new_block(dn);
	if (err || need_put)
		nbfs_put_dnode(dn);
	return err;
}

int nbfs_get_block(struct dnode_of_data *dn, pgoff_t index)
{
	struct extent_info ei  = {0,0,0};
	struct inode *inode = dn->inode;

	if (nbfs_lookup_extent_cache(inode, index, &ei)) {
		dn->data_blkaddr = ei.blk + index - ei.fofs;
		return 0;
	}

	return nbfs_reserve_block(dn, index);
}

struct page *nbfs_get_read_data_page(struct inode *inode, pgoff_t index,
						int op_flags, bool for_write)
{
	struct address_space *mapping = inode->i_mapping;
	struct dnode_of_data dn;
	struct page *page;
	struct extent_info ei = {0,0,0};
	int err;

	page = nbfs_grab_cache_page(mapping, index, for_write);
	if (!page)
		return ERR_PTR(-ENOMEM);

	if (nbfs_lookup_extent_cache(inode, index, &ei)) {
		dn.data_blkaddr = ei.blk + index - ei.fofs;
		goto got_it;
	}

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = nbfs_get_dnode_of_data(&dn, index, LOOKUP_NODE);
	if (err)
		goto put_err;
	nbfs_put_dnode(&dn);

	if (unlikely(dn.data_blkaddr == NULL_ADDR)) {
		err = -ENOENT;
		goto put_err;
	}
got_it:
	if (PageUptodate(page)) {
		unlock_page(page);
		return page;
	}

	/*
	 * A new dentry page is allocated but not able to be written, since its
	 * new inode page couldn't be allocated due to -ENOSPC.
	 * In such the case, its blkaddr can be remained as NEW_ADDR.
	 * see, nbfs_add_link -> nbfs_get_new_data_page ->
	 * nbfs_init_inode_metadata.
	 */
	if (dn.data_blkaddr == NEW_ADDR) {
		zero_user_segment(page, 0, PAGE_SIZE);
		if (!PageUptodate(page))
			SetPageUptodate(page);
		unlock_page(page);
		return page;
	}

	err = nbfs_submit_page_read(inode, page, dn.data_blkaddr);
	if (err)
		goto put_err;
	return page;

put_err:
	nbfs_put_page(page, 1);
	return ERR_PTR(err);
}

struct page *nbfs_find_data_page(struct inode *inode, pgoff_t index)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;

	page = find_get_page(mapping, index);
	if (page && PageUptodate(page))
		return page;
	nbfs_put_page(page, 0);

	page = nbfs_get_read_data_page(inode, index, 0, false);
	if (IS_ERR(page))
		return page;

	if (PageUptodate(page))
		return page;

	wait_on_page_locked(page);
	if (unlikely(!PageUptodate(page))) {
		nbfs_put_page(page, 0);
		return ERR_PTR(-EIO);
	}
	return page;
}

/*
 * If it tries to access a hole, return an error.
 * Because, the callers, functions in dir.c and GC, should be able to know
 * whether this page exists or not.
 */
struct page *nbfs_get_lock_data_page(struct inode *inode, pgoff_t index,
							bool for_write)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
repeat:
	page = nbfs_get_read_data_page(inode, index, 0, for_write);
	if (IS_ERR(page))
		return page;

	/* wait for read completion */
	lock_page(page);
	if (unlikely(page->mapping != mapping)) {
		nbfs_put_page(page, 1);
		goto repeat;
	}
	if (unlikely(!PageUptodate(page))) {
		nbfs_put_page(page, 1);
		return ERR_PTR(-EIO);
	}
	return page;
}

/*
 * Caller ensures that this data page is never allocated.
 * A new zero-filled data page is allocated in the page cache.
 *
 * Also, caller should grab and release a rwsem by calling nbfs_lock_op() and
 * nbfs_unlock_op().
 * Note that, ipage is set only by make_empty_dir, and if any error occur,
 * ipage should be released by this function.
 */
struct page *nbfs_get_new_data_page(struct inode *inode,
		struct page *ipage, pgoff_t index, bool new_i_size)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	struct dnode_of_data dn;
	int err;

	page = nbfs_grab_cache_page(mapping, index, true);
	if (!page) {
		/*
		 * before exiting, we should make sure ipage will be released
		 * if any error occur.
		 */
		nbfs_put_page(ipage, 1);
		return ERR_PTR(-ENOMEM);
	}

	set_new_dnode(&dn, inode, ipage, NULL, 0);
	err = nbfs_reserve_block(&dn, index);
	if (err) {
		nbfs_put_page(page, 1);
		return ERR_PTR(err);
	}
	if (!ipage)
		nbfs_put_dnode(&dn);

	if (PageUptodate(page))
		goto got_it;

	if (dn.data_blkaddr == NEW_ADDR) {
		zero_user_segment(page, 0, PAGE_SIZE);
		if (!PageUptodate(page))
			SetPageUptodate(page);
	} else {
		nbfs_put_page(page, 1);

		/* if ipage exists, blkaddr should be NEW_ADDR */
		nbfs_bug_on(NBFS_I_SB(inode), ipage);
		page = nbfs_get_lock_data_page(inode, index, true);
		if (IS_ERR(page))
			return page;
	}
got_it:
	if (new_i_size && i_size_read(inode) <
				((loff_t)(index + 1) << PAGE_SHIFT))
		nbfs_i_size_write(inode, ((loff_t)(index + 1) << PAGE_SHIFT));
	return page;
}

static int __allocate_data_block(struct dnode_of_data *dn, int seg_type)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dn->inode);
	struct nbfs_summary sum;
	struct node_info ni;
	block_t old_blkaddr;
	blkcnt_t count = 1;
	int err;

	if (unlikely(is_inode_flag_set(dn->inode, FI_NO_ALLOC)))
		return -EPERM;

	err = nbfs_get_node_info(sbi, dn->nid, &ni);
	if (err)
		return err;

	dn->data_blkaddr = datablock_addr(dn->inode,
				dn->node_page, dn->ofs_in_node);
	if (dn->data_blkaddr != NULL_ADDR)
		goto alloc;

	if (unlikely((err = inc_valid_block_count(sbi, dn->inode, &count))))
		return err;

alloc:
	set_summary(&sum, dn->nid, dn->ofs_in_node, ni.version);
	old_blkaddr = dn->data_blkaddr;
	nbfs_allocate_data_block(sbi, NULL, old_blkaddr, &dn->data_blkaddr,
					&sum, seg_type, NULL, false);
	if (GET_SEGNO(sbi, old_blkaddr) != NULL_SEGNO)
		invalidate_mapping_pages(META_MAPPING(sbi),
					old_blkaddr, old_blkaddr);
	nbfs_set_data_blkaddr(dn);

	/*
	 * i_size will be updated by direct_IO. Otherwise, we'll get stale
	 * data from unwritten block via dio_read.
	 */
	return 0;
}

int nbfs_preallocate_blocks(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct nbfs_map_blocks map;
	int flag;
	int err = 0;
	bool direct_io = iocb->ki_flags & IOCB_DIRECT;

	/* convert inline data for Direct I/O*/
	if (direct_io) {
		err = nbfs_convert_inline_inode(inode);
		if (err)
			return err;
	}

	if (direct_io && allow_outplace_dio(inode, iocb, from))
		return 0;

	if (is_inode_flag_set(inode, FI_NO_PREALLOC))
		return 0;

	map.m_lblk = NBFS_BLK_ALIGN(iocb->ki_pos);
	map.m_len = NBFS_BYTES_TO_BLK(iocb->ki_pos + iov_iter_count(from));
	if (map.m_len > map.m_lblk)
		map.m_len -= map.m_lblk;
	else
		map.m_len = 0;

	map.m_next_pgofs = NULL;
	map.m_next_extent = NULL;
	map.m_seg_type = NO_CHECK_TYPE;
	map.m_may_create = true;

	if (direct_io) {
		map.m_seg_type = nbfs_rw_hint_to_seg_type(iocb->ki_hint);
		flag = nbfs_force_buffered_io(inode, iocb, from) ?
					NBFS_GET_BLOCK_PRE_AIO :
					NBFS_GET_BLOCK_PRE_DIO;
		goto map_blocks;
	}
	if (iocb->ki_pos + iov_iter_count(from) > MAX_INLINE_DATA(inode)) {
		err = nbfs_convert_inline_inode(inode);
		if (err)
			return err;
	}
	if (nbfs_has_inline_data(inode))
		return err;

	flag = NBFS_GET_BLOCK_PRE_AIO;

map_blocks:
	err = nbfs_map_blocks(inode, &map, 1, flag);
	if (map.m_len > 0 && err == -ENOSPC) {
		if (!direct_io)
			set_inode_flag(inode, FI_NO_PREALLOC);
		err = 0;
	}
	return err;
}

void __do_map_lock(struct nbfs_sb_info *sbi, int flag, bool lock)
{
	if (flag == NBFS_GET_BLOCK_PRE_AIO) {
		if (lock)
			down_read(&sbi->node_change);
		else
			up_read(&sbi->node_change);
	} else {
		if (lock)
			nbfs_lock_op(sbi);
		else
			nbfs_unlock_op(sbi);
	}
}

/*
 * nbfs_map_blocks() now supported readahead/bmap/rw direct_IO with
 * nbfs_map_blocks structure.
 * If original data blocks are allocated, then give them to blockdev.
 * Otherwise,
 *     a. preallocate requested block addresses
 *     b. do not use extent cache for better performance
 *     c. give the block addresses to blockdev
 */
int nbfs_map_blocks(struct inode *inode, struct nbfs_map_blocks *map,
						int create, int flag)
{
	unsigned int maxblocks = map->m_len;
	struct dnode_of_data dn;
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	int mode = map->m_may_create ? ALLOC_NODE : LOOKUP_NODE;
	pgoff_t pgofs, end_offset, end;
	int err = 0, ofs = 1;
	unsigned int ofs_in_node, last_ofs_in_node;
	blkcnt_t prealloc;
	struct extent_info ei = {0,0,0};
	block_t blkaddr;
	unsigned int start_pgofs;

	if (!maxblocks)
		return 0;

	map->m_len = 0;
	map->m_flags = 0;

	/* it only supports block size == page size */
	pgofs =	(pgoff_t)map->m_lblk;
	end = pgofs + maxblocks;

	if (!create && nbfs_lookup_extent_cache(inode, pgofs, &ei)) {
		if (test_opt(sbi, LFS) && flag == NBFS_GET_BLOCK_DIO &&
							map->m_may_create)
			goto next_dnode;

		map->m_pblk = ei.blk + pgofs - ei.fofs;
		map->m_len = min((pgoff_t)maxblocks, ei.fofs + ei.len - pgofs);
		map->m_flags = NBFS_MAP_MAPPED;
		if (map->m_next_extent)
			*map->m_next_extent = pgofs + map->m_len;

		/* for hardware encryption, but to avoid potential issue in future */
		if (flag == NBFS_GET_BLOCK_DIO)
			nbfs_wait_on_block_writeback_range(inode,
						map->m_pblk, map->m_len);
		goto out;
	}

next_dnode:
	if (map->m_may_create)
		__do_map_lock(sbi, flag, true);

	/* When reading holes, we need its node page */
	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = nbfs_get_dnode_of_data(&dn, pgofs, mode);
	if (err) {
		if (flag == NBFS_GET_BLOCK_BMAP)
			map->m_pblk = 0;
		if (err == -ENOENT) {
			err = 0;
			if (map->m_next_pgofs)
				*map->m_next_pgofs =
					nbfs_get_next_page_offset(&dn, pgofs);
			if (map->m_next_extent)
				*map->m_next_extent =
					nbfs_get_next_page_offset(&dn, pgofs);
		}
		goto unlock_out;
	}

	start_pgofs = pgofs;
	prealloc = 0;
	last_ofs_in_node = ofs_in_node = dn.ofs_in_node;
	end_offset = ADDRS_PER_PAGE(dn.node_page, inode);

next_block:
	blkaddr = datablock_addr(dn.inode, dn.node_page, dn.ofs_in_node);

	if (__is_valid_data_blkaddr(blkaddr) &&
		!nbfs_is_valid_blkaddr(sbi, blkaddr, DATA_GENERIC)) {
		err = -EFAULT;
		goto sync_out;
	}

	if (is_valid_data_blkaddr(sbi, blkaddr)) {
		/* use out-place-update for driect IO under LFS mode */
		if (test_opt(sbi, LFS) && flag == NBFS_GET_BLOCK_DIO &&
							map->m_may_create) {
			err = __allocate_data_block(&dn, map->m_seg_type);
			if (!err) {
				blkaddr = dn.data_blkaddr;
				set_inode_flag(inode, FI_APPEND_WRITE);
			}
		}
	} else {
		if (create) {
			if (unlikely(nbfs_cp_error(sbi))) {
				err = -EIO;
				goto sync_out;
			}
			if (flag == NBFS_GET_BLOCK_PRE_AIO) {
				if (blkaddr == NULL_ADDR) {
					prealloc++;
					last_ofs_in_node = dn.ofs_in_node;
				}
			} else {
				WARN_ON(flag != NBFS_GET_BLOCK_PRE_DIO &&
					flag != NBFS_GET_BLOCK_DIO);
				err = __allocate_data_block(&dn,
							map->m_seg_type);
				if (!err)
					set_inode_flag(inode, FI_APPEND_WRITE);
			}
			if (err)
				goto sync_out;
			map->m_flags |= NBFS_MAP_NEW;
			blkaddr = dn.data_blkaddr;
		} else {
			if (flag == NBFS_GET_BLOCK_BMAP) {
				map->m_pblk = 0;
				goto sync_out;
			}
			if (flag == NBFS_GET_BLOCK_PRECACHE)
				goto sync_out;
			if (flag == NBFS_GET_BLOCK_FIEMAP &&
						blkaddr == NULL_ADDR) {
				if (map->m_next_pgofs)
					*map->m_next_pgofs = pgofs + 1;
				goto sync_out;
			}
			if (flag != NBFS_GET_BLOCK_FIEMAP) {
				/* for defragment case */
				if (map->m_next_pgofs)
					*map->m_next_pgofs = pgofs + 1;
				goto sync_out;
			}
		}
	}

	if (flag == NBFS_GET_BLOCK_PRE_AIO)
		goto skip;

	if (map->m_len == 0) {
		/* preallocated unwritten block should be mapped for fiemap. */
		if (blkaddr == NEW_ADDR)
			map->m_flags |= NBFS_MAP_UNWRITTEN;
		map->m_flags |= NBFS_MAP_MAPPED;

		map->m_pblk = blkaddr;
		map->m_len = 1;
	} else if ((map->m_pblk != NEW_ADDR &&
			blkaddr == (map->m_pblk + ofs)) ||
			(map->m_pblk == NEW_ADDR && blkaddr == NEW_ADDR) ||
			flag == NBFS_GET_BLOCK_PRE_DIO) {
		ofs++;
		map->m_len++;
	} else {
		goto sync_out;
	}

skip:
	dn.ofs_in_node++;
	pgofs++;

	/* preallocate blocks in batch for one dnode page */
	if (flag == NBFS_GET_BLOCK_PRE_AIO &&
			(pgofs == end || dn.ofs_in_node == end_offset)) {

		dn.ofs_in_node = ofs_in_node;
		err = nbfs_reserve_new_blocks(&dn, prealloc);
		if (err)
			goto sync_out;

		map->m_len += dn.ofs_in_node - ofs_in_node;
		if (prealloc && dn.ofs_in_node != last_ofs_in_node + 1) {
			err = -ENOSPC;
			goto sync_out;
		}
		dn.ofs_in_node = end_offset;
	}

	if (pgofs >= end)
		goto sync_out;
	else if (dn.ofs_in_node < end_offset)
		goto next_block;

	if (flag == NBFS_GET_BLOCK_PRECACHE) {
		if (map->m_flags & NBFS_MAP_MAPPED) {
			unsigned int ofs = start_pgofs - map->m_lblk;

			nbfs_update_extent_cache_range(&dn,
				start_pgofs, map->m_pblk + ofs,
				map->m_len - ofs);
		}
	}

	nbfs_put_dnode(&dn);

	if (map->m_may_create) {
		__do_map_lock(sbi, flag, false);
		nbfs_balance_fs(sbi, dn.node_changed);
	}
	goto next_dnode;

sync_out:

	/* for hardware encryption, but to avoid potential issue in future */
	if (flag == NBFS_GET_BLOCK_DIO && map->m_flags & NBFS_MAP_MAPPED)
		nbfs_wait_on_block_writeback_range(inode,
						map->m_pblk, map->m_len);

	if (flag == NBFS_GET_BLOCK_PRECACHE) {
		if (map->m_flags & NBFS_MAP_MAPPED) {
			unsigned int ofs = start_pgofs - map->m_lblk;

			nbfs_update_extent_cache_range(&dn,
				start_pgofs, map->m_pblk + ofs,
				map->m_len - ofs);
		}
		if (map->m_next_extent)
			*map->m_next_extent = pgofs + 1;
	}
	nbfs_put_dnode(&dn);
unlock_out:
	if (map->m_may_create) {
		__do_map_lock(sbi, flag, false);
		nbfs_balance_fs(sbi, dn.node_changed);
	}
out:
	trace_nbfs_map_blocks(inode, map, err);
	return err;
}

bool nbfs_overwrite_io(struct inode *inode, loff_t pos, size_t len)
{
	struct nbfs_map_blocks map;
	block_t last_lblk;
	int err;

	if (pos + len > i_size_read(inode))
		return false;

	map.m_lblk = NBFS_BYTES_TO_BLK(pos);
	map.m_next_pgofs = NULL;
	map.m_next_extent = NULL;
	map.m_seg_type = NO_CHECK_TYPE;
	map.m_may_create = false;
	last_lblk = NBFS_BLK_ALIGN(pos + len);

	while (map.m_lblk < last_lblk) {
		map.m_len = last_lblk - map.m_lblk;
		err = nbfs_map_blocks(inode, &map, 0, NBFS_GET_BLOCK_DEFAULT);
		if (err || map.m_len == 0)
			return false;
		map.m_lblk += map.m_len;
	}
	return true;
}

static int __get_data_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh, int create, int flag,
			pgoff_t *next_pgofs, int seg_type, bool may_write)
{
	struct nbfs_map_blocks map;
	int err;

	map.m_lblk = iblock;
	map.m_len = bh->b_size >> inode->i_blkbits;
	map.m_next_pgofs = next_pgofs;
	map.m_next_extent = NULL;
	map.m_seg_type = seg_type;
	map.m_may_create = may_write;

	err = nbfs_map_blocks(inode, &map, create, flag);
	if (!err) {
		map_bh(bh, inode->i_sb, map.m_pblk);
		bh->b_state = (bh->b_state & ~NBFS_MAP_FLAGS) | map.m_flags;
		bh->b_size = (u64)map.m_len << inode->i_blkbits;
	}
	return err;
}

static int get_data_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create, int flag,
			pgoff_t *next_pgofs)
{
	return __get_data_block(inode, iblock, bh_result, create,
							flag, next_pgofs,
							NO_CHECK_TYPE, create);
}

static int get_data_block_dio_write(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create)
{
	return __get_data_block(inode, iblock, bh_result, create,
				NBFS_GET_BLOCK_DIO, NULL,
				nbfs_rw_hint_to_seg_type(inode->i_write_hint),
				true);
}

static int get_data_block_dio(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create)
{
	return __get_data_block(inode, iblock, bh_result, create,
				NBFS_GET_BLOCK_DIO, NULL,
				nbfs_rw_hint_to_seg_type(inode->i_write_hint),
				false);
}

static int get_data_block_bmap(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create)
{
	/* Block number less than NBFS MAX BLOCKS */
	if (unlikely(iblock >= NBFS_I_SB(inode)->max_file_blocks))
		return -EFBIG;

	return __get_data_block(inode, iblock, bh_result, create,
						NBFS_GET_BLOCK_BMAP, NULL,
						NO_CHECK_TYPE, create);
}

static inline sector_t logical_to_blk(struct inode *inode, loff_t offset)
{
	return (offset >> inode->i_blkbits);
}

static inline loff_t blk_to_logical(struct inode *inode, sector_t blk)
{
	return (blk << inode->i_blkbits);
}

static int nbfs_xattr_fiemap(struct inode *inode,
				struct fiemap_extent_info *fieinfo)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	struct page *page;
	struct node_info ni;
	__u64 phys = 0, len;
	__u32 flags;
	nid_t xnid = NBFS_I(inode)->i_xattr_nid;
	int err = 0;

	if (nbfs_has_inline_xattr(inode)) {
		int offset;

		page = nbfs_grab_cache_page(NODE_MAPPING(sbi),
						inode->i_ino, false);
		if (!page)
			return -ENOMEM;

		err = nbfs_get_node_info(sbi, inode->i_ino, &ni);
		if (err) {
			nbfs_put_page(page, 1);
			return err;
		}

		phys = (__u64)blk_to_logical(inode, ni.blk_addr);
		offset = offsetof(struct nbfs_inode, i_addr) +
					sizeof(__le32) * (DEF_ADDRS_PER_INODE -
					get_inline_xattr_addrs(inode));

		phys += offset;
		len = inline_xattr_size(inode);

		nbfs_put_page(page, 1);

		flags = FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_NOT_ALIGNED;

		if (!xnid)
			flags |= FIEMAP_EXTENT_LAST;

		err = fiemap_fill_next_extent(fieinfo, 0, phys, len, flags);
		if (err || err == 1)
			return err;
	}

	if (xnid) {
		page = nbfs_grab_cache_page(NODE_MAPPING(sbi), xnid, false);
		if (!page)
			return -ENOMEM;

		err = nbfs_get_node_info(sbi, xnid, &ni);
		if (err) {
			nbfs_put_page(page, 1);
			return err;
		}

		phys = (__u64)blk_to_logical(inode, ni.blk_addr);
		len = inode->i_sb->s_blocksize;

		nbfs_put_page(page, 1);

		flags = FIEMAP_EXTENT_LAST;
	}

	if (phys)
		err = fiemap_fill_next_extent(fieinfo, 0, phys, len, flags);

	return (err < 0 ? err : 0);
}

int nbfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 len)
{
	struct buffer_head map_bh;
	sector_t start_blk, last_blk;
	pgoff_t next_pgofs;
	u64 logical = 0, phys = 0, size = 0;
	u32 flags = 0;
	int ret = 0;

	if (fieinfo->fi_flags & FIEMAP_FLAG_CACHE) {
		ret = nbfs_precache_extents(inode);
		if (ret)
			return ret;
	}

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR);
	if (ret)
		return ret;

	inode_lock(inode);

	if (fieinfo->fi_flags & FIEMAP_FLAG_XATTR) {
		ret = nbfs_xattr_fiemap(inode, fieinfo);
		goto out;
	}

	if (nbfs_has_inline_data(inode)) {
		ret = nbfs_inline_data_fiemap(inode, fieinfo, start, len);
		if (ret != -EAGAIN)
			goto out;
	}

	if (logical_to_blk(inode, len) == 0)
		len = blk_to_logical(inode, 1);

	start_blk = logical_to_blk(inode, start);
	last_blk = logical_to_blk(inode, start + len - 1);

next:
	memset(&map_bh, 0, sizeof(struct buffer_head));
	map_bh.b_size = len;

	ret = get_data_block(inode, start_blk, &map_bh, 0,
					NBFS_GET_BLOCK_FIEMAP, &next_pgofs);
	if (ret)
		goto out;

	/* HOLE */
	if (!buffer_mapped(&map_bh)) {
		start_blk = next_pgofs;

		if (blk_to_logical(inode, start_blk) < blk_to_logical(inode,
					NBFS_I_SB(inode)->max_file_blocks))
			goto prep_next;

		flags |= FIEMAP_EXTENT_LAST;
	}

	if (size) {
		if (IS_ENCRYPTED(inode))
			flags |= FIEMAP_EXTENT_DATA_ENCRYPTED;

		ret = fiemap_fill_next_extent(fieinfo, logical,
				phys, size, flags);
	}

	if (start_blk > last_blk || ret)
		goto out;

	logical = blk_to_logical(inode, start_blk);
	phys = blk_to_logical(inode, map_bh.b_blocknr);
	size = map_bh.b_size;
	flags = 0;
	if (buffer_unwritten(&map_bh))
		flags = FIEMAP_EXTENT_UNWRITTEN;

	start_blk += logical_to_blk(inode, size);

prep_next:
	cond_resched();
	if (fatal_signal_pending(current))
		ret = -EINTR;
	else
		goto next;
out:
	if (ret == 1)
		ret = 0;

	inode_unlock(inode);
	return ret;
}

/*
 * This function was originally taken from fs/mpage.c, and customized for nbfs.
 * Major change was from block_size == page_size in nbfs by default.
 *
 * Note that the aops->readpages() function is ONLY used for read-ahead. If
 * this function ever deviates from doing just read-ahead, it should either
 * use ->readpage() or do the necessary surgery to decouple ->readpages()
 * from read-ahead.
 */
static int nbfs_mpage_readpages(struct address_space *mapping,
			struct list_head *pages, struct page *page,
			unsigned nr_pages, bool is_readahead)
{
	struct bio *bio = NULL;
	sector_t last_block_in_bio = 0;
	struct inode *inode = mapping->host;
	const unsigned blkbits = inode->i_blkbits;
	const unsigned blocksize = 1 << blkbits;
	sector_t block_in_file;
	sector_t last_block;
	sector_t last_block_in_file;
	sector_t block_nr;
	struct nbfs_map_blocks map;

	map.m_pblk = 0;
	map.m_lblk = 0;
	map.m_len = 0;
	map.m_flags = 0;
	map.m_next_pgofs = NULL;
	map.m_next_extent = NULL;
	map.m_seg_type = NO_CHECK_TYPE;
	map.m_may_create = false;

	for (; nr_pages; nr_pages--) {
		if (pages) {
			page = list_last_entry(pages, struct page, lru);

			prefetchw(&page->flags);
			list_del(&page->lru);
			if (add_to_page_cache_lru(page, mapping,
						  page->index,
						  readahead_gfp_mask(mapping)))
				goto next_page;
		}

		block_in_file = (sector_t)page->index;
		last_block = block_in_file + nr_pages;
		last_block_in_file = (i_size_read(inode) + blocksize - 1) >>
								blkbits;
		if (last_block > last_block_in_file)
			last_block = last_block_in_file;

		/* just zeroing out page which is beyond EOF */
		if (block_in_file >= last_block)
			goto zero_out;
		/*
		 * Map blocks using the previous result first.
		 */
		if ((map.m_flags & NBFS_MAP_MAPPED) &&
				block_in_file > map.m_lblk &&
				block_in_file < (map.m_lblk + map.m_len))
			goto got_it;

		/*
		 * Then do more nbfs_map_blocks() calls until we are
		 * done with this page.
		 */
		map.m_lblk = block_in_file;
		map.m_len = last_block - block_in_file;

		if (nbfs_map_blocks(inode, &map, 0, NBFS_GET_BLOCK_DEFAULT))
			goto set_error_page;
got_it:
		if ((map.m_flags & NBFS_MAP_MAPPED)) {
			block_nr = map.m_pblk + block_in_file - map.m_lblk;
			SetPageMappedToDisk(page);

			if (!PageUptodate(page) && !cleancache_get_page(page)) {
				SetPageUptodate(page);
				goto confused;
			}

			if (!nbfs_is_valid_blkaddr(NBFS_I_SB(inode), block_nr,
								DATA_GENERIC))
				goto set_error_page;
		} else {
zero_out:
			zero_user_segment(page, 0, PAGE_SIZE);
			if (!PageUptodate(page))
				SetPageUptodate(page);
			unlock_page(page);
			goto next_page;
		}

		/*
		 * This page will go to BIO.  Do we need to send this
		 * BIO off first?
		 */
		if (bio && (last_block_in_bio != block_nr - 1 ||
			!__same_bdev(NBFS_I_SB(inode), block_nr, bio))) {
submit_and_realloc:
			__submit_bio(NBFS_I_SB(inode), bio, DATA);
			bio = NULL;
		}
		if (bio == NULL) {
			bio = nbfs_grab_read_bio(inode, block_nr, nr_pages,
					is_readahead ? REQ_RAHEAD : 0);
			if (IS_ERR(bio)) {
				bio = NULL;
				goto set_error_page;
			}
		}

		/*
		 * If the page is under writeback, we need to wait for
		 * its completion to see the correct decrypted data.
		 */
		nbfs_wait_on_block_writeback(inode, block_nr);

		if (bio_add_page(bio, page, blocksize, 0) < blocksize)
			goto submit_and_realloc;

		inc_page_count(NBFS_I_SB(inode), NBFS_RD_DATA);
		ClearPageError(page);
		last_block_in_bio = block_nr;
		goto next_page;
set_error_page:
		SetPageError(page);
		zero_user_segment(page, 0, PAGE_SIZE);
		unlock_page(page);
		goto next_page;
confused:
		if (bio) {
			__submit_bio(NBFS_I_SB(inode), bio, DATA);
			bio = NULL;
		}
		unlock_page(page);
next_page:
		if (pages)
			put_page(page);
	}
	BUG_ON(pages && !list_empty(pages));
	if (bio)
		__submit_bio(NBFS_I_SB(inode), bio, DATA);
	return 0;
}

static int nbfs_read_data_page(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	int ret = -EAGAIN;

	trace_nbfs_readpage(page, DATA);

	/* If the file has inline data, try to read it directly */
	if (nbfs_has_inline_data(inode))
		ret = nbfs_read_inline_data(inode, page);
	if (ret == -EAGAIN)
		ret = nbfs_mpage_readpages(page->mapping, NULL, page, 1, false);
	return ret;
}

static int nbfs_read_data_pages(struct file *file,
			struct address_space *mapping,
			struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct page *page = list_last_entry(pages, struct page, lru);

	trace_nbfs_readpages(inode, page, nr_pages);

	/* If the file has inline data, skip readpages */
	if (nbfs_has_inline_data(inode))
		return 0;

	return nbfs_mpage_readpages(mapping, pages, NULL, nr_pages, true);
}

static int encrypt_one_page(struct nbfs_io_info *fio)
{
	struct inode *inode = fio->page->mapping->host;
	struct page *mpage;
	gfp_t gfp_flags = GFP_NOFS;

	if (!nbfs_encrypted_file(inode))
		return 0;

	/* wait for GCed page writeback via META_MAPPING */
	nbfs_wait_on_block_writeback(inode, fio->old_blkaddr);

retry_encrypt:
	fio->encrypted_page = fscrypt_encrypt_page(inode, fio->page,
			PAGE_SIZE, 0, fio->page->index, gfp_flags);
	if (IS_ERR(fio->encrypted_page)) {
		/* flush pending IOs and wait for a while in the ENOMEM case */
		if (PTR_ERR(fio->encrypted_page) == -ENOMEM) {
			nbfs_flush_merged_writes(fio->sbi);
			congestion_wait(BLK_RW_ASYNC, HZ/50);
			gfp_flags |= __GFP_NOFAIL;
			goto retry_encrypt;
		}
		return PTR_ERR(fio->encrypted_page);
	}

	mpage = find_lock_page(META_MAPPING(fio->sbi), fio->old_blkaddr);
	if (mpage) {
		if (PageUptodate(mpage))
			memcpy(page_address(mpage),
				page_address(fio->encrypted_page), PAGE_SIZE);
		nbfs_put_page(mpage, 1);
	}
	return 0;
}

static inline bool check_inplace_update_policy(struct inode *inode,
				struct nbfs_io_info *fio)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	unsigned int policy = SM_I(sbi)->ipu_policy;

	if (policy & (0x1 << NBFS_IPU_FORCE))
		return true;
	if (policy & (0x1 << NBFS_IPU_SSR) && nbfs_need_SSR(sbi))
		return true;
	if (policy & (0x1 << NBFS_IPU_UTIL) &&
			utilization(sbi) > SM_I(sbi)->min_ipu_util)
		return true;
	if (policy & (0x1 << NBFS_IPU_SSR_UTIL) && nbfs_need_SSR(sbi) &&
			utilization(sbi) > SM_I(sbi)->min_ipu_util)
		return true;

	/*
	 * IPU for rewrite async pages
	 */
	if (policy & (0x1 << NBFS_IPU_ASYNC) &&
			fio && fio->op == REQ_OP_WRITE &&
			!(fio->op_flags & REQ_SYNC) &&
			!IS_ENCRYPTED(inode))
		return true;

	/* this is only set during fdatasync */
	if (policy & (0x1 << NBFS_IPU_FSYNC) &&
			is_inode_flag_set(inode, FI_NEED_IPU))
		return true;

	if (unlikely(fio && is_sbi_flag_set(sbi, SBI_CP_DISABLED) &&
			!nbfs_is_checkpointed_data(sbi, fio->old_blkaddr)))
		return true;

	return false;
}

bool nbfs_should_update_inplace(struct inode *inode, struct nbfs_io_info *fio)
{
	if (nbfs_is_pinned_file(inode))
		return true;

	/* if this is cold file, we should overwrite to avoid fragmentation */
	if (file_is_cold(inode))
		return true;

	return check_inplace_update_policy(inode, fio);
}

bool nbfs_should_update_outplace(struct inode *inode, struct nbfs_io_info *fio)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);

	if (test_opt(sbi, LFS))
		return true;
	if (S_ISDIR(inode->i_mode))
		return true;
	if (IS_NOQUOTA(inode))
		return true;
	if (nbfs_is_atomic_file(inode))
		return true;
	if (fio) {
		if (is_cold_data(fio->page))
			return true;
		if (IS_ATOMIC_WRITTEN_PAGE(fio->page))
			return true;
		if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED) &&
			nbfs_is_checkpointed_data(sbi, fio->old_blkaddr)))
			return true;
	}
	return false;
}

static inline bool need_inplace_update(struct nbfs_io_info *fio)
{
	struct inode *inode = fio->page->mapping->host;

	if (nbfs_should_update_outplace(inode, fio))
		return false;

	return nbfs_should_update_inplace(inode, fio);
}

#ifdef USE_NBFS
int nbfs_do_write_data_page_withoob(struct nbfs_io_info *fio)
{
	struct page *page = fio->page;
	struct inode *inode = page->mapping->host;
	struct dnode_of_data dn;
	struct extent_info ei = {0,0,0};
	struct node_info ni;
	bool ipu_force = false;
	int err = 0;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	if (need_inplace_update(fio) &&
			nbfs_lookup_extent_cache(inode, page->index, &ei)) {
		fio->old_blkaddr = ei.blk + page->index - ei.fofs;

		if (!nbfs_is_valid_blkaddr(fio->sbi, fio->old_blkaddr,
							DATA_GENERIC))
			return -EFAULT;

		ipu_force = true;
		fio->need_lock = LOCK_DONE;
		goto got_it;
	}

	/* Deadlock due to between page->lock and nbfs_lock_op */
	if (fio->need_lock == LOCK_REQ && !nbfs_trylock_op(fio->sbi))
		return -EAGAIN;

	err = nbfs_get_dnode_of_data(&dn, page->index, LOOKUP_NODE);
	if (err)
		goto out;

	fio->old_blkaddr = dn.data_blkaddr;

	/* This page is already truncated */
	if (fio->old_blkaddr == NULL_ADDR) {
		ClearPageUptodate(page);
		clear_cold_data(page);
		goto out_writepage;
	}
got_it:
	if (__is_valid_data_blkaddr(fio->old_blkaddr) &&
		!nbfs_is_valid_blkaddr(fio->sbi, fio->old_blkaddr,
							DATA_GENERIC)) {
		err = -EFAULT;
		goto out_writepage;
	}
	/*
	 * If current allocation needs SSR,
	 * it had better in-place writes for updated data.
	 */
	if (ipu_force || (is_valid_data_blkaddr(fio->sbi, fio->old_blkaddr) &&
					need_inplace_update(fio))) {
		err = encrypt_one_page(fio);
		if (err)
			goto out_writepage;

		set_page_writeback(page);
		ClearPageError(page);
		nbfs_put_dnode(&dn);
		if (fio->need_lock == LOCK_REQ)
			nbfs_unlock_op(fio->sbi);
		err = nbfs_inplace_write_data(fio);
		if (err) {
			if (nbfs_encrypted_file(inode))
				fscrypt_pullback_bio_page(&fio->encrypted_page,
									true);
			if (PageWriteback(page))
				end_page_writeback(page);
		}
		trace_nbfs_do_write_data_page(fio->page, IPU);
		set_inode_flag(inode, FI_UPDATE_WRITE);
		return err;
	}

	if (fio->need_lock == LOCK_RETRY) {
		if (!nbfs_trylock_op(fio->sbi)) {
			err = -EAGAIN;
			goto out_writepage;
		}
		fio->need_lock = LOCK_REQ;
	}

	err = nbfs_get_node_info(fio->sbi, dn.nid, &ni);
	if (err)
		goto out_writepage;

	fio->version = ni.version;

	err = encrypt_one_page(fio);
	if (err)
		goto out_writepage;

#ifndef NBFS_ULTRAFAST_MODE
#ifdef NBFS_NOMERGE_HINT_FOR_DATABIO
	if (!test_opt(NBFS_P_SB(page), NOBARRIER))
		fio->op_flags |= REQ_FUA | REQ_NOMERGE;
#else
	if (!test_opt(NBFS_P_SB(page), NOBARRIER))
		fio->op_flags |= REQ_FUA;
#endif
#endif

	set_page_writeback(page);
	ClearPageError(page);

	/* LFS mode write path */
	nbfs_outplace_write_data_withoob(&dn, fio);
	trace_nbfs_do_write_data_page(page, OPU);
	set_inode_flag(inode, FI_APPEND_WRITE);
	if (page->index == 0)
		set_inode_flag(inode, FI_FIRST_BLOCK_WRITTEN);
out_writepage:
	nbfs_put_dnode(&dn);
out:
	if (fio->need_lock == LOCK_REQ)
		nbfs_unlock_op(fio->sbi);
	return err;
}
#endif

int nbfs_do_write_data_page(struct nbfs_io_info *fio)
{
	struct page *page = fio->page;
	struct inode *inode = page->mapping->host;
	struct dnode_of_data dn;
	struct extent_info ei = {0,0,0};
	struct node_info ni;
	bool ipu_force = false;
	int err = 0;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	if (need_inplace_update(fio) &&
			nbfs_lookup_extent_cache(inode, page->index, &ei)) {
		fio->old_blkaddr = ei.blk + page->index - ei.fofs;

		if (!nbfs_is_valid_blkaddr(fio->sbi, fio->old_blkaddr,
							DATA_GENERIC))
			return -EFAULT;

		ipu_force = true;
		fio->need_lock = LOCK_DONE;
		goto got_it;
	}

	/* Deadlock due to between page->lock and nbfs_lock_op */
	if (fio->need_lock == LOCK_REQ && !nbfs_trylock_op(fio->sbi))
		return -EAGAIN;

	err = nbfs_get_dnode_of_data(&dn, page->index, LOOKUP_NODE);
	if (err)
		goto out;

	fio->old_blkaddr = dn.data_blkaddr;

	/* This page is already truncated */
	if (fio->old_blkaddr == NULL_ADDR) {
		ClearPageUptodate(page);
		clear_cold_data(page);
		goto out_writepage;
	}
got_it:
	if (__is_valid_data_blkaddr(fio->old_blkaddr) &&
		!nbfs_is_valid_blkaddr(fio->sbi, fio->old_blkaddr,
							DATA_GENERIC)) {
		err = -EFAULT;
		goto out_writepage;
	}
	/*
	 * If current allocation needs SSR,
	 * it had better in-place writes for updated data.
	 */
	if (ipu_force || (is_valid_data_blkaddr(fio->sbi, fio->old_blkaddr) &&
					need_inplace_update(fio))) {
		err = encrypt_one_page(fio);
		if (err)
			goto out_writepage;

		set_page_writeback(page);
		ClearPageError(page);
		nbfs_put_dnode(&dn);
		if (fio->need_lock == LOCK_REQ)
			nbfs_unlock_op(fio->sbi);
		err = nbfs_inplace_write_data(fio);
		if (err) {
			if (nbfs_encrypted_file(inode))
				fscrypt_pullback_bio_page(&fio->encrypted_page,
									true);
			if (PageWriteback(page))
				end_page_writeback(page);
		}
		trace_nbfs_do_write_data_page(fio->page, IPU);
		set_inode_flag(inode, FI_UPDATE_WRITE);
		return err;
	}

	if (fio->need_lock == LOCK_RETRY) {
		if (!nbfs_trylock_op(fio->sbi)) {
			err = -EAGAIN;
			goto out_writepage;
		}
		fio->need_lock = LOCK_REQ;
	}

	err = nbfs_get_node_info(fio->sbi, dn.nid, &ni);
	if (err)
		goto out_writepage;

	fio->version = ni.version;

	err = encrypt_one_page(fio);
	if (err)
		goto out_writepage;

	set_page_writeback(page);
	ClearPageError(page);

	/* LFS mode write path */
	nbfs_outplace_write_data(&dn, fio);
	trace_nbfs_do_write_data_page(page, OPU);
	set_inode_flag(inode, FI_APPEND_WRITE);
	if (page->index == 0)
		set_inode_flag(inode, FI_FIRST_BLOCK_WRITTEN);
out_writepage:
	nbfs_put_dnode(&dn);
out:
	if (fio->need_lock == LOCK_REQ)
		nbfs_unlock_op(fio->sbi);
	return err;
}

static int __write_data_page(struct page *page, bool *submitted,
				struct writeback_control *wbc,
				enum iostat_type io_type)
{
	struct inode *inode = page->mapping->host;
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index = ((unsigned long long) i_size)
							>> PAGE_SHIFT;
	loff_t psize = (page->index + 1) << PAGE_SHIFT;
	unsigned offset = 0;
	bool need_balance_fs = false;
	int err = 0;
	struct nbfs_io_info fio = {
		.sbi = sbi,
		.ino = inode->i_ino,
		.type = DATA,
		.op = REQ_OP_WRITE,
		.op_flags = wbc_to_write_flags(wbc),
		.old_blkaddr = NULL_ADDR,
		.page = page,
		.encrypted_page = NULL,
		.submitted = false,
		.need_lock = LOCK_RETRY,
		.io_type = io_type,
		.io_wbc = wbc,
		.oobinfo = NULL,
		.force_cp = false,
	};

	trace_nbfs_writepage(page, DATA);
	//pr_notice("%s, iotype=%d\n", __func__, io_type);

	/* we should bypass data pages to proceed the kworkder jobs */
	if (unlikely(nbfs_cp_error(sbi))) {
		mapping_set_error(page->mapping, -EIO);
		/*
		 * don't drop any dirty dentry pages for keeping lastest
		 * directory structure.
		 */
		if (S_ISDIR(inode->i_mode))
			goto redirty_out;
		goto out;
	}

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto redirty_out;

	if (page->index < end_index)
		goto write;

	/*
	 * If the offset is out-of-range of file size,
	 * this page does not have to be written to disk.
	 */
	offset = i_size & (PAGE_SIZE - 1);
	if ((page->index >= end_index + 1) || !offset)
		goto out;

	zero_user_segment(page, offset, PAGE_SIZE);
write:
	if (nbfs_is_drop_cache(inode))
		goto out;
	/* we should not write 0'th page having journal header */
	if (nbfs_is_volatile_file(inode) && (!page->index ||
			(!wbc->for_reclaim &&
			nbfs_available_free_memory(sbi, BASE_CHECK))))
		goto redirty_out;

	/* Dentry blocks are controlled by checkpoint */
	if (S_ISDIR(inode->i_mode)) {
		fio.need_lock = LOCK_DONE;
		err = nbfs_do_write_data_page(&fio);
		goto done;
	}

	if (!wbc->for_reclaim)
		need_balance_fs = true;
	else if (has_not_enough_free_secs(sbi, 0, 0))
		goto redirty_out;
	else
		set_inode_flag(inode, FI_HOT_DATA);

	err = -EAGAIN;
	if (nbfs_has_inline_data(inode)) {
		err = nbfs_write_inline_data(inode, page);
		if (!err)
			goto out;
	}

	if (err == -EAGAIN) {
		err = nbfs_do_write_data_page(&fio);
		if (err == -EAGAIN) {
			fio.need_lock = LOCK_REQ;
			err = nbfs_do_write_data_page(&fio);
		}
	}

	if (err) {
		file_set_keep_isize(inode);
	} else {
		down_write(&NBFS_I(inode)->i_sem);
		if (NBFS_I(inode)->last_disk_size < psize)
			NBFS_I(inode)->last_disk_size = psize;
		up_write(&NBFS_I(inode)->i_sem);
	}

done:
	if (err && err != -ENOENT)
		goto redirty_out;

out:
	inode_dec_dirty_pages(inode);
	if (err) {
		ClearPageUptodate(page);
		clear_cold_data(page);
	}

	if (wbc->for_reclaim) {
		nbfs_submit_merged_write_cond(sbi, NULL, page, 0, DATA);
		clear_inode_flag(inode, FI_HOT_DATA);
		nbfs_remove_dirty_inode(inode);
		submitted = NULL;
	}

	unlock_page(page);
	if (!S_ISDIR(inode->i_mode) && !IS_NOQUOTA(inode))
		nbfs_balance_fs(sbi, need_balance_fs);

	if (unlikely(nbfs_cp_error(sbi))) {
		nbfs_submit_merged_write(sbi, DATA);
		submitted = NULL;
	}

	if (submitted)
		*submitted = fio.submitted;

	return 0;

redirty_out:
	redirty_page_for_writepage(wbc, page);
	/*
	 * pageout() in MM traslates EAGAIN, so calls handle_write_error()
	 * -> mapping_set_error() -> set_bit(AS_EIO, ...).
	 * file_write_and_wait_range() will see EIO error, which is critical
	 * to return value of fsync() followed by atomic_write failure to user.
	 */
	if (!err || wbc->for_reclaim)
		return AOP_WRITEPAGE_ACTIVATE;
	unlock_page(page);
	return err;
}

static int nbfs_write_data_page(struct page *page,
					struct writeback_control *wbc)
{
	return __write_data_page(page, NULL, wbc, FS_DATA_IO);
}

/*
 * This function was copied from write_cche_pages from mm/page-writeback.c.
 * The major change is making write step of cold data page separately from
 * warm/hot data page.
 */
static int nbfs_write_cache_pages(struct address_space *mapping,
					struct writeback_control *wbc,
					enum iostat_type io_type)
{
	int ret = 0;
	int done = 0;
	struct pagevec pvec;
	struct nbfs_sb_info *sbi = NBFS_M_SB(mapping);
	int nr_pages;
	pgoff_t uninitialized_var(writeback_index);
	pgoff_t index;
	pgoff_t end;		/* Inclusive */
	pgoff_t done_index;
	int cycled;
	int range_whole = 0;
	xa_mark_t tag;
	int nwritten = 0;

	pagevec_init(&pvec);

	if (get_dirty_pages(mapping->host) <=
				SM_I(NBFS_M_SB(mapping))->min_hot_blocks)
		set_inode_flag(mapping->host, FI_HOT_DATA);
	else
		clear_inode_flag(mapping->host, FI_HOT_DATA);

	if (wbc->range_cyclic) {
		writeback_index = mapping->writeback_index; /* prev offset */
		index = writeback_index;
		if (index == 0)
			cycled = 1;
		else
			cycled = 0;
		end = -1;
	} else {
		index = wbc->range_start >> PAGE_SHIFT;
		end = wbc->range_end >> PAGE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
		cycled = 1; /* ignore range_cyclic tests */
	}
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else
		tag = PAGECACHE_TAG_DIRTY;
retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, index, end);
	done_index = index;
	while (!done && (index <= end)) {
		int i;

		nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index, end,
				tag);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];
			bool submitted = false;

			/* give a priority to WB_SYNC threads */
			if (atomic_read(&sbi->wb_sync_req[DATA]) &&
					wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}

			done_index = page->index;
retry_write:
			lock_page(page);

			if (unlikely(page->mapping != mapping)) {
continue_unlock:
				unlock_page(page);
				continue;
			}

			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (PageWriteback(page)) {
				if (wbc->sync_mode != WB_SYNC_NONE)
					nbfs_wait_on_page_writeback(page,
							DATA, true, true);
				else
					goto continue_unlock;
			}

			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			ret = __write_data_page(page, &submitted, wbc, io_type);
			if (unlikely(ret)) {
				/*
				 * keep nr_to_write, since vfs uses this to
				 * get # of written pages.
				 */
				if (ret == AOP_WRITEPAGE_ACTIVATE) {
					unlock_page(page);
					ret = 0;
					continue;
				} else if (ret == -EAGAIN) {
					ret = 0;
					if (wbc->sync_mode == WB_SYNC_ALL) {
						cond_resched();
						congestion_wait(BLK_RW_ASYNC,
									HZ/50);
						goto retry_write;
					}
					continue;
				}
				done_index = page->index + 1;
				done = 1;
				break;
			} else if (submitted) {
				nwritten++;
			}

			if (--wbc->nr_to_write <= 0 &&
					wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	if (!cycled && !done) {
		cycled = 1;
		index = 0;
		end = writeback_index - 1;
		goto retry;
	}
	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

	if (nwritten)
		nbfs_submit_merged_write_cond(NBFS_M_SB(mapping), mapping->host,
								NULL, 0, DATA);

	return ret;
}

static inline bool __should_serialize_io(struct inode *inode,
					struct writeback_control *wbc)
{
	if (!S_ISREG(inode->i_mode))
		return false;
	if (IS_NOQUOTA(inode))
		return false;
	if (wbc->sync_mode != WB_SYNC_ALL)
		return true;
	if (get_dirty_pages(inode) >= SM_I(NBFS_I_SB(inode))->min_seq_blocks)
		return true;
	return false;
}

static int __nbfs_write_data_pages(struct address_space *mapping,
						struct writeback_control *wbc,
						enum iostat_type io_type)
{
	struct inode *inode = mapping->host;
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	struct blk_plug plug;
	int ret;
	bool locked = false;

	/* deal with chardevs and other special file */
	if (!mapping->a_ops->writepage)
		return 0;

	/* skip writing if there is no dirty page in this inode */
	if (!get_dirty_pages(inode) && wbc->sync_mode == WB_SYNC_NONE)
		return 0;

	/* during POR, we don't need to trigger writepage at all. */
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto skip_write;

	if ((S_ISDIR(inode->i_mode) || IS_NOQUOTA(inode)) &&
			wbc->sync_mode == WB_SYNC_NONE &&
			get_dirty_pages(inode) < nr_pages_to_skip(sbi, DATA) &&
			nbfs_available_free_memory(sbi, DIRTY_DENTS))
		goto skip_write;

	/* skip writing during file defragment */
	if (is_inode_flag_set(inode, FI_DO_DEFRAG))
		goto skip_write;

	trace_nbfs_writepages(mapping->host, wbc, DATA);

	/* to avoid spliting IOs due to mixed WB_SYNC_ALL and WB_SYNC_NONE */
	if (wbc->sync_mode == WB_SYNC_ALL)
		atomic_inc(&sbi->wb_sync_req[DATA]);
	else if (atomic_read(&sbi->wb_sync_req[DATA]))
		goto skip_write;

	if (__should_serialize_io(inode, wbc)) {
		mutex_lock(&sbi->writepages);
		locked = true;
	}

	blk_start_plug(&plug);
	ret = nbfs_write_cache_pages(mapping, wbc, io_type);
	blk_finish_plug(&plug);

	if (locked)
		mutex_unlock(&sbi->writepages);

	if (wbc->sync_mode == WB_SYNC_ALL)
		atomic_dec(&sbi->wb_sync_req[DATA]);
	/*
	 * if some pages were truncated, we cannot guarantee its mapping->host
	 * to detect pending bios.
	 */

	nbfs_remove_dirty_inode(inode);
	return ret;

skip_write:
	wbc->pages_skipped += get_dirty_pages(inode);
	trace_nbfs_writepages(mapping->host, wbc, DATA);
	return 0;
}

static int nbfs_write_data_pages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;

	//pr_notice("%s, ino=%lu start(%llu) end(%llu) nrwrite(%lu)\n",
	//		__func__, inode->i_ino,
	//		wbc->range_start, wbc->range_end, wbc->nr_to_write);

	return __nbfs_write_data_pages(mapping, wbc,
			NBFS_I(inode)->cp_task == current ?
			FS_CP_DATA_IO : FS_DATA_IO);
}

static void nbfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;
	loff_t i_size = i_size_read(inode);

	if (to > i_size) {
		down_write(&NBFS_I(inode)->i_gc_rwsem[WRITE]);
		down_write(&NBFS_I(inode)->i_mmap_sem);

		truncate_pagecache(inode, i_size);
		if (!IS_NOQUOTA(inode))
			nbfs_truncate_blocks(inode, i_size, true);

		up_write(&NBFS_I(inode)->i_mmap_sem);
		up_write(&NBFS_I(inode)->i_gc_rwsem[WRITE]);
	}
}

static int prepare_write_begin(struct nbfs_sb_info *sbi,
			struct page *page, loff_t pos, unsigned len,
			block_t *blk_addr, bool *node_changed)
{
	struct inode *inode = page->mapping->host;
	pgoff_t index = page->index;
	struct dnode_of_data dn;
	struct page *ipage;
	bool locked = false;
	struct extent_info ei = {0,0,0};
	int err = 0;
	int flag;

	/*
	 * we already allocated all the blocks, so we don't need to get
	 * the block addresses when there is no need to fill the page.
	 */
	if (!nbfs_has_inline_data(inode) && len == PAGE_SIZE &&
			!is_inode_flag_set(inode, FI_NO_PREALLOC))
		return 0;

	/* nbfs_lock_op avoids race between write CP and convert_inline_page */
	if (nbfs_has_inline_data(inode) && pos + len > MAX_INLINE_DATA(inode))
		flag = NBFS_GET_BLOCK_DEFAULT;
	else
		flag = NBFS_GET_BLOCK_PRE_AIO;

	if (nbfs_has_inline_data(inode) ||
			(pos & PAGE_MASK) >= i_size_read(inode)) {
		__do_map_lock(sbi, flag, true);
		locked = true;
	}
restart:
	/* check inline_data */
	ipage = nbfs_get_node_page(sbi, inode->i_ino);
	if (IS_ERR(ipage)) {
		err = PTR_ERR(ipage);
		goto unlock_out;
	}

	set_new_dnode(&dn, inode, ipage, ipage, 0);

	if (nbfs_has_inline_data(inode)) {
		if (pos + len <= MAX_INLINE_DATA(inode)) {
			nbfs_do_read_inline_data(page, ipage);
			set_inode_flag(inode, FI_DATA_EXIST);
			if (inode->i_nlink)
				set_inline_node(ipage);
		} else {
			err = nbfs_convert_inline_page(&dn, page);
			if (err)
				goto out;
			if (dn.data_blkaddr == NULL_ADDR)
				err = nbfs_get_block(&dn, index);
		}
	} else if (locked) {
		err = nbfs_get_block(&dn, index);
	} else {
		if (nbfs_lookup_extent_cache(inode, index, &ei)) {
			dn.data_blkaddr = ei.blk + index - ei.fofs;
		} else {
			/* hole case */
			err = nbfs_get_dnode_of_data(&dn, index, LOOKUP_NODE);
			if (err || dn.data_blkaddr == NULL_ADDR) {
				nbfs_put_dnode(&dn);
				__do_map_lock(sbi, NBFS_GET_BLOCK_PRE_AIO,
								true);
				WARN_ON(flag != NBFS_GET_BLOCK_PRE_AIO);
				locked = true;
				goto restart;
			}
		}
	}

	/* convert_inline_page can make node_changed */
	*blk_addr = dn.data_blkaddr;
	*node_changed = dn.node_changed;
out:
	nbfs_put_dnode(&dn);
unlock_out:
	if (locked)
		__do_map_lock(sbi, flag, false);
	return err;
}

static int nbfs_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	struct page *page = NULL;
	pgoff_t index = ((unsigned long long) pos) >> PAGE_SHIFT;
	bool need_balance = false, drop_atomic = false;
	block_t blkaddr = NULL_ADDR;
	int err = 0;

	trace_nbfs_write_begin(inode, pos, len, flags);

	err = nbfs_is_checkpoint_ready(sbi);
	if (err)
		goto fail;

	if ((nbfs_is_atomic_file(inode) &&
			!nbfs_available_free_memory(sbi, INMEM_PAGES)) ||
			is_inode_flag_set(inode, FI_ATOMIC_REVOKE_REQUEST)) {
		err = -ENOMEM;
		drop_atomic = true;
		goto fail;
	}

	/*
	 * We should check this at this moment to avoid deadlock on inode page
	 * and #0 page. The locking rule for inline_data conversion should be:
	 * lock_page(page #0) -> lock_page(inode_page)
	 */
	if (index != 0) {
		err = nbfs_convert_inline_inode(inode);
		if (err)
			goto fail;
	}
repeat:
	/*
	 * Do not use grab_cache_page_write_begin() to avoid deadlock due to
	 * wait_for_stable_page. Will wait that below with our IO control.
	 */
	page = nbfs_pagecache_get_page(mapping, index,
				FGP_LOCK | FGP_WRITE | FGP_CREAT, GFP_NOFS);
	if (!page) {
		err = -ENOMEM;
		goto fail;
	}

	*pagep = page;

	err = prepare_write_begin(sbi, page, pos, len,
					&blkaddr, &need_balance);
	if (err)
		goto fail;

	if (need_balance && !IS_NOQUOTA(inode) &&
			has_not_enough_free_secs(sbi, 0, 0)) {
		unlock_page(page);
		nbfs_balance_fs(sbi, true);
		lock_page(page);
		if (page->mapping != mapping) {
			/* The page got truncated from under us */
			nbfs_put_page(page, 1);
			goto repeat;
		}
	}

	nbfs_wait_on_page_writeback(page, DATA, false, true);

	if (len == PAGE_SIZE || PageUptodate(page))
		return 0;

	if (!(pos & (PAGE_SIZE - 1)) && (pos + len) >= i_size_read(inode)) {
		zero_user_segment(page, len, PAGE_SIZE);
		return 0;
	}

	if (blkaddr == NEW_ADDR) {
		zero_user_segment(page, 0, PAGE_SIZE);
		SetPageUptodate(page);
	} else {
		err = nbfs_submit_page_read(inode, page, blkaddr);
		if (err)
			goto fail;

		lock_page(page);
		if (unlikely(page->mapping != mapping)) {
			nbfs_put_page(page, 1);
			goto repeat;
		}
		if (unlikely(!PageUptodate(page))) {
			err = -EIO;
			goto fail;
		}
	}
	return 0;

fail:
	nbfs_put_page(page, 1);
	nbfs_write_failed(mapping, pos + len);
	if (drop_atomic)
		nbfs_drop_inmem_pages_all(sbi, false);
	return err;
}

static int nbfs_write_end(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;

	trace_nbfs_write_end(inode, pos, len, copied);

	/*
	 * This should be come from len == PAGE_SIZE, and we expect copied
	 * should be PAGE_SIZE. Otherwise, we treat it with zero copied and
	 * let generic_perform_write() try to copy data again through copied=0.
	 */
	if (!PageUptodate(page)) {
		if (unlikely(copied != len))
			copied = 0;
		else
			SetPageUptodate(page);
	}
	if (!copied)
		goto unlock_out;

	set_page_dirty(page);

	if (pos + copied > i_size_read(inode))
		nbfs_i_size_write(inode, pos + copied);
unlock_out:
	nbfs_put_page(page, 1);
	nbfs_update_time(NBFS_I_SB(inode), REQ_TIME);
	return copied;
}

static int check_direct_IO(struct inode *inode, struct iov_iter *iter,
			   loff_t offset)
{
	unsigned i_blkbits = READ_ONCE(inode->i_blkbits);
	unsigned blkbits = i_blkbits;
	unsigned blocksize_mask = (1 << blkbits) - 1;
	unsigned long align = offset | iov_iter_alignment(iter);
	struct block_device *bdev = inode->i_sb->s_bdev;

	if (align & blocksize_mask) {
		if (bdev)
			blkbits = blksize_bits(bdev_logical_block_size(bdev));
		blocksize_mask = (1 << blkbits) - 1;
		if (align & blocksize_mask)
			return -EINVAL;
		return 1;
	}
	return 0;
}

static void nbfs_dio_end_io(struct bio *bio)
{
	struct nbfs_private_dio *dio = bio->bi_private;

	dec_page_count(NBFS_I_SB(dio->inode),
			dio->write ? NBFS_DIO_WRITE : NBFS_DIO_READ);

	bio->bi_private = dio->orig_private;
	bio->bi_end_io = dio->orig_end_io;

	kvfree(dio);

	bio_endio(bio);
}

static void nbfs_dio_submit_bio(struct bio *bio, struct inode *inode,
							loff_t file_offset)
{
	struct nbfs_private_dio *dio;
	bool write = (bio_op(bio) == REQ_OP_WRITE);

	dio = nbfs_kzalloc(NBFS_I_SB(inode),
			sizeof(struct nbfs_private_dio), GFP_NOFS);
	if (!dio)
		goto out;

	dio->inode = inode;
	dio->orig_end_io = bio->bi_end_io;
	dio->orig_private = bio->bi_private;
	dio->write = write;

	bio->bi_end_io = nbfs_dio_end_io;
	bio->bi_private = dio;

	inc_page_count(NBFS_I_SB(inode),
			write ? NBFS_DIO_WRITE : NBFS_DIO_READ);

	submit_bio(bio);
	return;
out:
	bio->bi_status = BLK_STS_IOERR;
	bio_endio(bio);
}

static ssize_t nbfs_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct address_space *mapping = iocb->ki_filp->f_mapping;
	struct inode *inode = mapping->host;
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	struct nbfs_inode_info *fi = NBFS_I(inode);
	size_t count = iov_iter_count(iter);
	loff_t offset = iocb->ki_pos;
	int rw = iov_iter_rw(iter);
	int err;
	enum rw_hint hint = iocb->ki_hint;
	int whint_mode = NBFS_OPTION(sbi).whint_mode;
	bool do_opu;

	err = check_direct_IO(inode, iter, offset);
	if (err)
		return err < 0 ? err : 0;

	if (nbfs_force_buffered_io(inode, iocb, iter))
		return 0;

	do_opu = allow_outplace_dio(inode, iocb, iter);

	trace_nbfs_direct_IO_enter(inode, offset, count, rw);

	if (rw == WRITE && whint_mode == WHINT_MODE_OFF)
		iocb->ki_hint = WRITE_LIFE_NOT_SET;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!down_read_trylock(&fi->i_gc_rwsem[rw])) {
			iocb->ki_hint = hint;
			err = -EAGAIN;
			goto out;
		}
		if (do_opu && !down_read_trylock(&fi->i_gc_rwsem[READ])) {
			up_read(&fi->i_gc_rwsem[rw]);
			iocb->ki_hint = hint;
			err = -EAGAIN;
			goto out;
		}
	} else {
		down_read(&fi->i_gc_rwsem[rw]);
		if (do_opu)
			down_read(&fi->i_gc_rwsem[READ]);
	}

	err = __blockdev_direct_IO(iocb, inode, inode->i_sb->s_bdev,
			iter, rw == WRITE ? get_data_block_dio_write :
			get_data_block_dio, NULL, nbfs_dio_submit_bio,
			DIO_LOCKING | DIO_SKIP_HOLES);

	if (do_opu)
		up_read(&fi->i_gc_rwsem[READ]);

	up_read(&fi->i_gc_rwsem[rw]);

	if (rw == WRITE) {
		if (whint_mode == WHINT_MODE_OFF)
			iocb->ki_hint = hint;
		if (err > 0) {
			nbfs_update_iostat(NBFS_I_SB(inode), APP_DIRECT_IO,
									err);
			if (!do_opu)
				set_inode_flag(inode, FI_UPDATE_WRITE);
		} else if (err < 0) {
			nbfs_write_failed(mapping, offset + count);
		}
	}

out:
	trace_nbfs_direct_IO_exit(inode, offset, count, rw, err);

	return err;
}

void nbfs_invalidate_page(struct page *page, unsigned int offset,
							unsigned int length)
{
	struct inode *inode = page->mapping->host;
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);

	if (inode->i_ino >= NBFS_ROOT_INO(sbi) &&
		(offset % PAGE_SIZE || length != PAGE_SIZE))
		return;

	if (PageDirty(page)) {
		if (inode->i_ino == NBFS_META_INO(sbi)) {
			dec_page_count(sbi, NBFS_DIRTY_META);
		} else if (inode->i_ino == NBFS_NODE_INO(sbi)) {
			dec_page_count(sbi, NBFS_DIRTY_NODES);
		} else {
			inode_dec_dirty_pages(inode);
			nbfs_remove_dirty_inode(inode);
		}
	}

	clear_cold_data(page);

	if (IS_ATOMIC_WRITTEN_PAGE(page))
		return nbfs_drop_inmem_page(inode, page);

	nbfs_clear_page_private(page);
}

int nbfs_release_page(struct page *page, gfp_t wait)
{
	/* If this is dirty page, keep PagePrivate */
	if (PageDirty(page))
		return 0;

	/* This is atomic written page, keep Private */
	if (IS_ATOMIC_WRITTEN_PAGE(page))
		return 0;

	clear_cold_data(page);
	nbfs_clear_page_private(page);
	return 1;
}

static int nbfs_set_data_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;

	trace_nbfs_set_page_dirty(page, DATA);

	if (!PageUptodate(page))
		SetPageUptodate(page);

	if (nbfs_is_atomic_file(inode) && !nbfs_is_commit_atomic_write(inode)) {
		if (!IS_ATOMIC_WRITTEN_PAGE(page)) {
			nbfs_register_inmem_page(inode, page);
			return 1;
		}
		/*
		 * Previously, this page has been registered, we just
		 * return here.
		 */
		return 0;
	}

	if (!PageDirty(page)) {
		__set_page_dirty_nobuffers(page);
		nbfs_update_dirty_page(inode, page);
		return 1;
	}
	return 0;
}

static sector_t nbfs_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;

	if (nbfs_has_inline_data(inode))
		return 0;

	/* make sure allocating whole blocks */
	if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
		filemap_write_and_wait(mapping);

	return generic_block_bmap(mapping, block, get_data_block_bmap);
}

#ifdef CONFIG_MIGRATION
#include <linux/migrate.h>

int nbfs_migrate_page(struct address_space *mapping,
		struct page *newpage, struct page *page, enum migrate_mode mode)
{
	int rc, extra_count;
	struct nbfs_inode_info *fi = NBFS_I(mapping->host);
	bool atomic_written = IS_ATOMIC_WRITTEN_PAGE(page);

	BUG_ON(PageWriteback(page));

	/* migrating an atomic written page is safe with the inmem_lock hold */
	if (atomic_written) {
		if (mode != MIGRATE_SYNC)
			return -EBUSY;
		if (!mutex_trylock(&fi->inmem_lock))
			return -EAGAIN;
	}

	/* one extra reference was held for atomic_write page */
	extra_count = atomic_written ? 1 : 0;
	rc = migrate_page_move_mapping(mapping, newpage,
				page, mode, extra_count);
	if (rc != MIGRATEPAGE_SUCCESS) {
		if (atomic_written)
			mutex_unlock(&fi->inmem_lock);
		return rc;
	}

	if (atomic_written) {
		struct inmem_pages *cur;
		list_for_each_entry(cur, &fi->inmem_pages, list)
			if (cur->page == page) {
				cur->page = newpage;
				break;
			}
		mutex_unlock(&fi->inmem_lock);
		put_page(page);
		get_page(newpage);
	}

	if (PagePrivate(page)) {
		nbfs_set_page_private(newpage, page_private(page));
		nbfs_clear_page_private(page);
	}

	if (mode != MIGRATE_SYNC_NO_COPY)
		migrate_page_copy(newpage, page);
	else
		migrate_page_states(newpage, page);

	return MIGRATEPAGE_SUCCESS;
}
#endif

const struct address_space_operations nbfs_dblock_aops = {
	.readpage	= nbfs_read_data_page,
	.readpages	= nbfs_read_data_pages,
	.writepage	= nbfs_write_data_page,
	.writepages	= nbfs_write_data_pages,
	.write_begin	= nbfs_write_begin,
	.write_end	= nbfs_write_end,
	.set_page_dirty	= nbfs_set_data_page_dirty,
	.invalidatepage	= nbfs_invalidate_page,
	.releasepage	= nbfs_release_page,
	.direct_IO	= nbfs_direct_IO,
	.bmap		= nbfs_bmap,
#ifdef CONFIG_MIGRATION
	.migratepage    = nbfs_migrate_page,
#endif
};

void nbfs_clear_page_cache_dirty_tag(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	unsigned long flags;

	xa_lock_irqsave(&mapping->i_pages, flags);
	__xa_clear_mark(&mapping->i_pages, page_index(page),
						PAGECACHE_TAG_DIRTY);
	xa_unlock_irqrestore(&mapping->i_pages, flags);
}

int __init nbfs_init_post_read_processing(void)
{
	bio_post_read_ctx_cache = KMEM_CACHE(bio_post_read_ctx, 0);
	if (!bio_post_read_ctx_cache)
		goto fail;
	bio_post_read_ctx_pool =
		mempool_create_slab_pool(NUM_PREALLOC_POST_READ_CTXS,
					 bio_post_read_ctx_cache);
	if (!bio_post_read_ctx_pool)
		goto fail_free_cache;

	bio_write_node_info = nbfs_kmem_cache_create("node_info_per_bio_list",
			sizeof(struct bio_wn_info_header));
	if (!bio_write_node_info)
		goto fail_destroy_mempool;
	bio_write_node_entries = nbfs_kmem_cache_create("node_info_entries",
			sizeof(struct bio_wn_info_entry));
	if (!bio_write_node_entries)
		goto fail_destroy_bio_write_node_info;
	return 0;
	kmem_cache_destroy(bio_write_node_entries);
fail_destroy_bio_write_node_info:
	kmem_cache_destroy(bio_write_node_info);
fail_destroy_mempool:
	mempool_destroy(bio_post_read_ctx_pool);
fail_free_cache:
	kmem_cache_destroy(bio_post_read_ctx_cache);
fail:
	return -ENOMEM;
}

void __exit nbfs_destroy_post_read_processing(void)
{
	kmem_cache_destroy(bio_write_node_entries);
	kmem_cache_destroy(bio_write_node_info);
	mempool_destroy(bio_post_read_ctx_pool);
	kmem_cache_destroy(bio_post_read_ctx_cache);
}
