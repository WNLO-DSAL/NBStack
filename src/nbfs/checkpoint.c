// SPDX-License-Identifier: GPL-2.0
/*
 * fs/nbfs/checkpoint.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/nbfs_fs.h>
#include <linux/pagevec.h>
#include <linux/swap.h>

#include "nbfs.h"
#include "node.h"
#include "segment.h"
#include "trace.h"
#include <trace/events/nbfs.h>

static struct kmem_cache *ino_entry_slab;
struct kmem_cache *nbfs_inode_entry_slab;

void nbfs_stop_checkpoint(struct nbfs_sb_info *sbi, bool end_io)
{
	nbfs_build_fault_attr(sbi, 0, 0);
	set_ckpt_flags(sbi, CP_ERROR_FLAG);
	if (!end_io)
		nbfs_flush_merged_writes(sbi);
}

/*
 * We guarantee no failure on the returned page.
 */
struct page *nbfs_grab_meta_page(struct nbfs_sb_info *sbi, pgoff_t index)
{
	struct address_space *mapping = META_MAPPING(sbi);
	struct page *page = NULL;
repeat:
	page = nbfs_grab_cache_page(mapping, index, false);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	nbfs_wait_on_page_writeback(page, META, true, true);
	if (!PageUptodate(page))
		SetPageUptodate(page);
	return page;
}

/*
 * We guarantee no failure on the returned page.
 */
static struct page *__get_meta_page(struct nbfs_sb_info *sbi, pgoff_t index,
							bool is_meta)
{
	struct address_space *mapping = META_MAPPING(sbi);
	struct page *page;
	struct nbfs_io_info fio = {
		.sbi = sbi,
		.type = META,
		.op = REQ_OP_READ,
		.op_flags = REQ_META | REQ_PRIO,
		.old_blkaddr = index,
		.new_blkaddr = index,
		.encrypted_page = NULL,
		.is_meta = is_meta,
		.oobinfo = NULL,
		.force_cp = false,
	};
	int err;

	if (unlikely(!is_meta))
		fio.op_flags &= ~REQ_META;
repeat:
	page = nbfs_grab_cache_page(mapping, index, false);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	if (PageUptodate(page))
		goto out;

	fio.page = page;

	err = nbfs_submit_page_bio(&fio);
	if (err) {
		nbfs_put_page(page, 1);
		return ERR_PTR(err);
	}

	lock_page(page);
	if (unlikely(page->mapping != mapping)) {
		nbfs_put_page(page, 1);
		goto repeat;
	}

	if (unlikely(!PageUptodate(page))) {
		nbfs_put_page(page, 1);
		return ERR_PTR(-EIO);
	}
out:
	return page;
}

#ifdef USE_NBFS
static struct page *__get_meta_page_withoob(struct nbfs_sb_info *sbi, pgoff_t index,
							bool is_meta, unsigned long *poobinfo)
{
	struct address_space *mapping = META_MAPPING(sbi);
	struct page *page;
	struct nbfs_io_info fio = {
		.sbi = sbi,
		.type = META,
		.op = REQ_OP_READ,
		.op_flags = REQ_META | REQ_PRIO,
		.old_blkaddr = index,
		.new_blkaddr = index,
		.encrypted_page = NULL,
		.is_meta = is_meta,
		.oobinfo = NULL,
		.force_cp = false,
	};
	int err;

	if (unlikely(!is_meta))
		fio.op_flags &= ~REQ_META;
repeat:
	page = nbfs_grab_cache_page(mapping, index, false);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	if (PageUptodate(page))
		goto out;

	fio.page = page;
	fio.oobinfo = nbfs_allocate_extradata(GFP_NOFS);

	err = nbfs_submit_page_bio_withoob(&fio);
	if (err) {
		nbfs_free_extradata(fio.oobinfo);
		nbfs_put_page(page, 1);
		return ERR_PTR(err);
	}

	lock_page(page);
	if (unlikely(page->mapping != mapping)) {
		nbfs_free_extradata(fio.oobinfo);
		nbfs_put_page(page, 1);
		goto repeat;
	}

	if (unlikely(!PageUptodate(page))) {
		nbfs_free_extradata(fio.oobinfo);
		nbfs_put_page(page, 1);
		return ERR_PTR(-EIO);
	}
	*poobinfo = *(fio.oobinfo);
	nbfs_free_extradata(fio.oobinfo);
out:
	return page;
}

struct page *nbfs_get_tmp_page_recovery(struct nbfs_sb_info *sbi,
					pgoff_t index, unsigned long *poobinfo)
{
	return __get_meta_page_withoob(sbi, index, false, poobinfo);
}
#else
struct page *nbfs_get_tmp_page_recovery(struct nbfs_sb_info *sbi,
					pgoff_t index, unsigned long *poobinfo)
{
	return __get_meta_page(sbi, index, false);
}
#endif

struct page *nbfs_get_meta_page(struct nbfs_sb_info *sbi, pgoff_t index)
{
	return __get_meta_page(sbi, index, true);
}

struct page *nbfs_get_meta_page_nofail(struct nbfs_sb_info *sbi, pgoff_t index)
{
	struct page *page;
	int count = 0;

retry:
	page = __get_meta_page(sbi, index, true);
	if (IS_ERR(page)) {
		if (PTR_ERR(page) == -EIO &&
				++count <= DEFAULT_RETRY_IO_COUNT)
			goto retry;
		nbfs_stop_checkpoint(sbi, false);
	}
	return page;
}

/* for POR only */
struct page *nbfs_get_tmp_page(struct nbfs_sb_info *sbi, pgoff_t index)
{
	return __get_meta_page(sbi, index, false);
}


bool nbfs_is_valid_blkaddr(struct nbfs_sb_info *sbi,
					block_t blkaddr, int type)
{
	switch (type) {
	case META_NAT:
		break;
	case META_SIT:
		if (unlikely(blkaddr >= SIT_BLK_CNT(sbi)))
			return false;
		break;
	case META_SSA:
		if (unlikely(blkaddr >= MAIN_BLKADDR(sbi) ||
			blkaddr < SM_I(sbi)->ssa_blkaddr))
			return false;
		break;
	case META_CP:
		if (unlikely(blkaddr >= SIT_I(sbi)->sit_base_addr ||
			blkaddr < __start_cp_addr(sbi)))
			return false;
		break;
	case META_POR:
	case DATA_GENERIC:
		if (unlikely(blkaddr >= MAX_BLKADDR(sbi) ||
			blkaddr < MAIN_BLKADDR(sbi))) {
			if (type == DATA_GENERIC) {
				nbfs_msg(sbi->sb, KERN_WARNING,
					"access invalid blkaddr:%u", blkaddr);
				WARN_ON(1);
			}
			return false;
		}
		break;
	case META_GENERIC:
		if (unlikely(blkaddr < SEG0_BLKADDR(sbi) ||
			blkaddr >= MAIN_BLKADDR(sbi)))
			return false;
		break;
	default:
		BUG();
	}

	return true;
}

/*
 * Readahead CP/NAT/SIT/SSA pages
 */
int nbfs_ra_meta_pages(struct nbfs_sb_info *sbi, block_t start, int nrpages,
							int type, bool sync)
{
	struct page *page;
	block_t blkno = start;
	struct nbfs_io_info fio = {
		.sbi = sbi,
		.type = META,
		.op = REQ_OP_READ,
		.op_flags = sync ? (REQ_META | REQ_PRIO) : REQ_RAHEAD,
		.encrypted_page = NULL,
		.in_list = false,
		.is_meta = (type != META_POR),
		.oobinfo = NULL,
		.force_cp = false,
	};
	struct blk_plug plug;

	if (unlikely(type == META_POR))
		fio.op_flags &= ~REQ_META;

	blk_start_plug(&plug);
	for (; nrpages-- > 0; blkno++) {

		if (!nbfs_is_valid_blkaddr(sbi, blkno, type))
			goto out;

		switch (type) {
		case META_NAT:
			if (unlikely(blkno >=
					NAT_BLOCK_OFFSET(NM_I(sbi)->max_nid)))
				blkno = 0;
			/* get nat block addr */
			fio.new_blkaddr = current_nat_addr(sbi,
					blkno * NAT_ENTRY_PER_BLOCK);
			break;
		case META_SIT:
			/* get sit block addr */
			fio.new_blkaddr = current_sit_addr(sbi,
					blkno * SIT_ENTRY_PER_BLOCK);
			break;
		case META_SSA:
		case META_CP:
		case META_POR:
			fio.new_blkaddr = blkno;
			break;
		default:
			BUG();
		}

		page = nbfs_grab_cache_page(META_MAPPING(sbi),
						fio.new_blkaddr, false);
		if (!page)
			continue;
		if (PageUptodate(page)) {
			nbfs_put_page(page, 1);
			continue;
		}

		fio.page = page;
		nbfs_submit_page_bio(&fio);
		nbfs_put_page(page, 0);
	}
out:
	blk_finish_plug(&plug);
	return blkno - start;
}

void nbfs_ra_meta_pages_cond(struct nbfs_sb_info *sbi, pgoff_t index)
{
	struct page *page;
	bool readahead = false;

	page = find_get_page(META_MAPPING(sbi), index);
	if (!page || !PageUptodate(page))
		readahead = true;
	nbfs_put_page(page, 0);

	if (readahead)
		nbfs_ra_meta_pages(sbi, index, BIO_MAX_PAGES, META_POR, true);
}

static int __nbfs_write_meta_page(struct page *page,
				struct writeback_control *wbc,
				enum iostat_type io_type)
{
	struct nbfs_sb_info *sbi = NBFS_P_SB(page);

	trace_nbfs_writepage(page, META);

	if (unlikely(nbfs_cp_error(sbi)))
		goto redirty_out;
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto redirty_out;
	if (wbc->for_reclaim && page->index < GET_SUM_BLOCK(sbi, 0))
		goto redirty_out;

	nbfs_do_write_meta_page(sbi, page, io_type);
	dec_page_count(sbi, NBFS_DIRTY_META);

	if (wbc->for_reclaim)
		nbfs_submit_merged_write_cond(sbi, NULL, page, 0, META);

	unlock_page(page);

	if (unlikely(nbfs_cp_error(sbi)))
		nbfs_submit_merged_write(sbi, META);

	return 0;

redirty_out:
	redirty_page_for_writepage(wbc, page);
	return AOP_WRITEPAGE_ACTIVATE;
}

static int nbfs_write_meta_page(struct page *page,
				struct writeback_control *wbc)
{
	return __nbfs_write_meta_page(page, wbc, FS_META_IO);
}

static int nbfs_write_meta_pages(struct address_space *mapping,
				struct writeback_control *wbc)
{
	struct nbfs_sb_info *sbi = NBFS_M_SB(mapping);
	long diff, written;

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto skip_write;

	/* collect a number of dirty meta pages and write together */
	if (wbc->sync_mode != WB_SYNC_ALL &&
			get_pages(sbi, NBFS_DIRTY_META) <
					nr_pages_to_skip(sbi, META))
		goto skip_write;

	/* if locked failed, cp will flush dirty pages instead */
	if (!mutex_trylock(&sbi->cp_mutex))
		goto skip_write;

	trace_nbfs_writepages(mapping->host, wbc, META);
	diff = nr_pages_to_write(sbi, META, wbc);
	written = nbfs_sync_meta_pages(sbi, META, wbc->nr_to_write, FS_META_IO);
	mutex_unlock(&sbi->cp_mutex);
	wbc->nr_to_write = max((long)0, wbc->nr_to_write - written - diff);
	return 0;

skip_write:
	wbc->pages_skipped += get_pages(sbi, NBFS_DIRTY_META);
	trace_nbfs_writepages(mapping->host, wbc, META);
	return 0;
}

long nbfs_sync_meta_pages(struct nbfs_sb_info *sbi, enum page_type type,
				long nr_to_write, enum iostat_type io_type)
{
	struct address_space *mapping = META_MAPPING(sbi);
	pgoff_t index = 0, prev = ULONG_MAX;
	struct pagevec pvec;
	long nwritten = 0;
	int nr_pages;
	struct writeback_control wbc = {
		.for_reclaim = 0,
	};
	struct blk_plug plug;

	pagevec_init(&pvec);

	blk_start_plug(&plug);

	while ((nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
				PAGECACHE_TAG_DIRTY))) {
		int i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			if (prev == ULONG_MAX)
				prev = page->index - 1;
			if (nr_to_write != LONG_MAX && page->index != prev + 1) {
				pagevec_release(&pvec);
				goto stop;
			}

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

			nbfs_wait_on_page_writeback(page, META, true, true);

			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			if (__nbfs_write_meta_page(page, &wbc, io_type)) {
				unlock_page(page);
				break;
			}
			nwritten++;
			prev = page->index;
			if (unlikely(nwritten >= nr_to_write))
				break;
		}
		pagevec_release(&pvec);
		cond_resched();
	}
stop:
	if (nwritten)
		nbfs_submit_merged_write(sbi, type);

	blk_finish_plug(&plug);

	return nwritten;
}

static int nbfs_set_meta_page_dirty(struct page *page)
{
	trace_nbfs_set_page_dirty(page, META);

	if (!PageUptodate(page))
		SetPageUptodate(page);
	if (!PageDirty(page)) {
		__set_page_dirty_nobuffers(page);
		inc_page_count(NBFS_P_SB(page), NBFS_DIRTY_META);
		nbfs_set_page_private(page, 0);
		nbfs_trace_pid(page);
		return 1;
	}
	return 0;
}

const struct address_space_operations nbfs_meta_aops = {
	.writepage	= nbfs_write_meta_page,
	.writepages	= nbfs_write_meta_pages,
	.set_page_dirty	= nbfs_set_meta_page_dirty,
	.invalidatepage = nbfs_invalidate_page,
	.releasepage	= nbfs_release_page,
#ifdef CONFIG_MIGRATION
	.migratepage    = nbfs_migrate_page,
#endif
};

static void __add_ino_entry(struct nbfs_sb_info *sbi, nid_t ino,
						unsigned int devidx, int type)
{
	struct inode_management *im = &sbi->im[type];
	struct ino_entry *e, *tmp;

	tmp = nbfs_kmem_cache_alloc(ino_entry_slab, GFP_NOFS);

	radix_tree_preload(GFP_NOFS | __GFP_NOFAIL);

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	if (!e) {
		e = tmp;
		if (unlikely(radix_tree_insert(&im->ino_root, ino, e)))
			nbfs_bug_on(sbi, 1);

		memset(e, 0, sizeof(struct ino_entry));
		e->ino = ino;

		list_add_tail(&e->list, &im->ino_list);
		if (type != ORPHAN_INO)
			im->ino_num++;
	}

	if (type == FLUSH_INO)
		nbfs_set_bit(devidx, (char *)&e->dirty_device);

	spin_unlock(&im->ino_lock);
	radix_tree_preload_end();

	if (e != tmp)
		kmem_cache_free(ino_entry_slab, tmp);
}

static void __remove_ino_entry(struct nbfs_sb_info *sbi, nid_t ino, int type)
{
	struct inode_management *im = &sbi->im[type];
	struct ino_entry *e;

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	if (e) {
		list_del(&e->list);
		radix_tree_delete(&im->ino_root, ino);
		im->ino_num--;
		spin_unlock(&im->ino_lock);
		kmem_cache_free(ino_entry_slab, e);
		return;
	}
	spin_unlock(&im->ino_lock);
}

void nbfs_add_ino_entry(struct nbfs_sb_info *sbi, nid_t ino, int type)
{
	/* add new dirty ino entry into list */
	__add_ino_entry(sbi, ino, 0, type);
}

void nbfs_remove_ino_entry(struct nbfs_sb_info *sbi, nid_t ino, int type)
{
	/* remove dirty ino entry from list */
	__remove_ino_entry(sbi, ino, type);
}

/* mode should be APPEND_INO or UPDATE_INO */
bool nbfs_exist_written_data(struct nbfs_sb_info *sbi, nid_t ino, int mode)
{
	struct inode_management *im = &sbi->im[mode];
	struct ino_entry *e;

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	spin_unlock(&im->ino_lock);
	return e ? true : false;
}

void nbfs_release_ino_entry(struct nbfs_sb_info *sbi, bool all)
{
	struct ino_entry *e, *tmp;
	int i;

	for (i = all ? ORPHAN_INO : APPEND_INO; i < MAX_INO_ENTRY; i++) {
		struct inode_management *im = &sbi->im[i];

		spin_lock(&im->ino_lock);
		list_for_each_entry_safe(e, tmp, &im->ino_list, list) {
			list_del(&e->list);
			radix_tree_delete(&im->ino_root, e->ino);
			kmem_cache_free(ino_entry_slab, e);
			im->ino_num--;
		}
		spin_unlock(&im->ino_lock);
	}
}

void nbfs_set_dirty_device(struct nbfs_sb_info *sbi, nid_t ino,
					unsigned int devidx, int type)
{
	__add_ino_entry(sbi, ino, devidx, type);
}

bool nbfs_is_dirty_device(struct nbfs_sb_info *sbi, nid_t ino,
					unsigned int devidx, int type)
{
	struct inode_management *im = &sbi->im[type];
	struct ino_entry *e;
	bool is_dirty = false;

	spin_lock(&im->ino_lock);
	e = radix_tree_lookup(&im->ino_root, ino);
	if (e && nbfs_test_bit(devidx, (char *)&e->dirty_device))
		is_dirty = true;
	spin_unlock(&im->ino_lock);
	return is_dirty;
}

int nbfs_acquire_orphan_inode(struct nbfs_sb_info *sbi)
{
	struct inode_management *im = &sbi->im[ORPHAN_INO];
	int err = 0;

	spin_lock(&im->ino_lock);

	if (time_to_inject(sbi, FAULT_ORPHAN)) {
		spin_unlock(&im->ino_lock);
		nbfs_show_injection_info(FAULT_ORPHAN);
		return -ENOSPC;
	}

	if (unlikely(im->ino_num >= sbi->max_orphans))
		err = -ENOSPC;
	else
		im->ino_num++;
	spin_unlock(&im->ino_lock);

	return err;
}

void nbfs_release_orphan_inode(struct nbfs_sb_info *sbi)
{
	struct inode_management *im = &sbi->im[ORPHAN_INO];

	spin_lock(&im->ino_lock);
	nbfs_bug_on(sbi, im->ino_num == 0);
	im->ino_num--;
	spin_unlock(&im->ino_lock);
}

void nbfs_add_orphan_inode(struct inode *inode)
{
	/* add new orphan ino entry into list */
	__add_ino_entry(NBFS_I_SB(inode), inode->i_ino, 0, ORPHAN_INO);
	nbfs_update_inode_page(inode);
}

void nbfs_remove_orphan_inode(struct nbfs_sb_info *sbi, nid_t ino)
{
	/* remove orphan entry from orphan list */
	__remove_ino_entry(sbi, ino, ORPHAN_INO);
}

static int recover_orphan_inode(struct nbfs_sb_info *sbi, nid_t ino)
{
	struct inode *inode;
	struct node_info ni;
	int err;

	inode = nbfs_iget_retry(sbi->sb, ino);
	if (IS_ERR(inode)) {
		/*
		 * there should be a bug that we can't find the entry
		 * to orphan inode.
		 */
		nbfs_bug_on(sbi, PTR_ERR(inode) == -ENOENT);
		return PTR_ERR(inode);
	}

	err = dquot_initialize(inode);
	if (err) {
		iput(inode);
		goto err_out;
	}

	clear_nlink(inode);

	/* truncate all the data during iput */
	iput(inode);

	err = nbfs_get_node_info(sbi, ino, &ni);
	if (err)
		goto err_out;

	/* ENOMEM was fully retried in nbfs_evict_inode. */
	if (ni.blk_addr != NULL_ADDR) {
		err = -EIO;
		goto err_out;
	}
	return 0;

err_out:
	set_sbi_flag(sbi, SBI_NEED_FSCK);
	nbfs_msg(sbi->sb, KERN_WARNING,
			"%s: orphan failed (ino=%x), run fsck to fix.",
			__func__, ino);
	return err;
}

int nbfs_recover_orphan_inodes(struct nbfs_sb_info *sbi)
{
	block_t start_blk, orphan_blocks, i, j;
	unsigned int s_flags = sbi->sb->s_flags;
	int err = 0;
#ifdef CONFIG_QUOTA
	int quota_enabled;
#endif

	if (!is_set_ckpt_flags(sbi, CP_ORPHAN_PRESENT_FLAG))
		return 0;

	if (s_flags & SB_RDONLY) {
		nbfs_msg(sbi->sb, KERN_INFO, "orphan cleanup on readonly fs");
		sbi->sb->s_flags &= ~SB_RDONLY;
	}

#ifdef CONFIG_QUOTA
	/* Needed for iput() to work correctly and not trash data */
	sbi->sb->s_flags |= SB_ACTIVE;

	/*
	 * Turn on quotas which were not enabled for read-only mounts if
	 * filesystem has quota feature, so that they are updated correctly.
	 */
	quota_enabled = nbfs_enable_quota_files(sbi, s_flags & SB_RDONLY);
#endif

	start_blk = __start_cp_addr(sbi) + 1 + __cp_payload(sbi);
	orphan_blocks = __start_sum_addr(sbi) - 1 - __cp_payload(sbi);

	nbfs_ra_meta_pages(sbi, start_blk, orphan_blocks, META_CP, true);

	for (i = 0; i < orphan_blocks; i++) {
		struct page *page;
		struct nbfs_orphan_block *orphan_blk;

		page = nbfs_get_meta_page(sbi, start_blk + i);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto out;
		}

		orphan_blk = (struct nbfs_orphan_block *)page_address(page);
		for (j = 0; j < le32_to_cpu(orphan_blk->entry_count); j++) {
			nid_t ino = le32_to_cpu(orphan_blk->ino[j]);
			err = recover_orphan_inode(sbi, ino);
			if (err) {
				nbfs_put_page(page, 1);
				goto out;
			}
		}
		nbfs_put_page(page, 1);
	}
	/* clear Orphan Flag */
	clear_ckpt_flags(sbi, CP_ORPHAN_PRESENT_FLAG);
out:
	set_sbi_flag(sbi, SBI_IS_RECOVERED);

#ifdef CONFIG_QUOTA
	/* Turn quotas off */
	if (quota_enabled)
		nbfs_quota_off_umount(sbi->sb);
#endif
	sbi->sb->s_flags = s_flags; /* Restore SB_RDONLY status */

	return err;
}

static void write_orphan_inodes(struct nbfs_sb_info *sbi, block_t start_blk)
{
	struct list_head *head;
	struct nbfs_orphan_block *orphan_blk = NULL;
	unsigned int nentries = 0;
	unsigned short index = 1;
	unsigned short orphan_blocks;
	struct page *page = NULL;
	struct ino_entry *orphan = NULL;
	struct inode_management *im = &sbi->im[ORPHAN_INO];

	orphan_blocks = GET_ORPHAN_BLOCKS(im->ino_num);

	/*
	 * we don't need to do spin_lock(&im->ino_lock) here, since all the
	 * orphan inode operations are covered under nbfs_lock_op().
	 * And, spin_lock should be avoided due to page operations below.
	 */
	head = &im->ino_list;

	/* loop for each orphan inode entry and write them in Jornal block */
	list_for_each_entry(orphan, head, list) {
		if (!page) {
			page = nbfs_grab_meta_page(sbi, start_blk++);
			orphan_blk =
				(struct nbfs_orphan_block *)page_address(page);
			memset(orphan_blk, 0, sizeof(*orphan_blk));
		}

		orphan_blk->ino[nentries++] = cpu_to_le32(orphan->ino);

		if (nentries == NBFS_ORPHANS_PER_BLOCK) {
			/*
			 * an orphan block is full of 1020 entries,
			 * then we need to flush current orphan blocks
			 * and bring another one in memory
			 */
			orphan_blk->blk_addr = cpu_to_le16(index);
			orphan_blk->blk_count = cpu_to_le16(orphan_blocks);
			orphan_blk->entry_count = cpu_to_le32(nentries);
			set_page_dirty(page);
			nbfs_put_page(page, 1);
			index++;
			nentries = 0;
			page = NULL;
		}
	}

	if (page) {
		orphan_blk->blk_addr = cpu_to_le16(index);
		orphan_blk->blk_count = cpu_to_le16(orphan_blocks);
		orphan_blk->entry_count = cpu_to_le32(nentries);
		set_page_dirty(page);
		nbfs_put_page(page, 1);
	}
}

static int get_checkpoint_version(struct nbfs_sb_info *sbi, block_t cp_addr,
		struct nbfs_checkpoint **cp_block, struct page **cp_page,
		unsigned long long *version)
{
	unsigned long blk_size = sbi->blocksize;
	size_t crc_offset = 0;
	__u32 crc = 0;

	*cp_page = nbfs_get_meta_page(sbi, cp_addr);
	if (IS_ERR(*cp_page))
		return PTR_ERR(*cp_page);

	*cp_block = (struct nbfs_checkpoint *)page_address(*cp_page);

	crc_offset = le32_to_cpu((*cp_block)->checksum_offset);
	if (crc_offset > (blk_size - sizeof(__le32))) {
		nbfs_put_page(*cp_page, 1);
		nbfs_msg(sbi->sb, KERN_WARNING,
			"invalid crc_offset: %zu", crc_offset);
		return -EINVAL;
	}

	crc = cur_cp_crc(*cp_block);
	if (!nbfs_crc_valid(sbi, crc, *cp_block, crc_offset)) {
		nbfs_put_page(*cp_page, 1);
		nbfs_msg(sbi->sb, KERN_WARNING, "invalid crc value");
		return -EINVAL;
	}

	*version = cur_cp_version(*cp_block);
	return 0;
}

static struct page *validate_checkpoint(struct nbfs_sb_info *sbi,
				block_t cp_addr, unsigned long long *version)
{
	struct page *cp_page_1 = NULL, *cp_page_2 = NULL;
	struct nbfs_checkpoint *cp_block = NULL;
	unsigned long long cur_version = 0, pre_version = 0;
	int err;

	err = get_checkpoint_version(sbi, cp_addr, &cp_block,
					&cp_page_1, version);
	if (err)
		return NULL;

	if (le32_to_cpu(cp_block->cp_pack_total_block_count) >
					sbi->blocks_per_seg) {
		nbfs_msg(sbi->sb, KERN_WARNING,
			"invalid cp_pack_total_block_count:%u",
			le32_to_cpu(cp_block->cp_pack_total_block_count));
		goto invalid_cp;
	}
	pre_version = *version;

	cp_addr += le32_to_cpu(cp_block->cp_pack_total_block_count) - 1;
	err = get_checkpoint_version(sbi, cp_addr, &cp_block,
					&cp_page_2, version);
	if (err)
		goto invalid_cp;
	cur_version = *version;

	if (cur_version == pre_version) {
		*version = cur_version;
		nbfs_put_page(cp_page_2, 1);
		return cp_page_1;
	}
	nbfs_put_page(cp_page_2, 1);
invalid_cp:
	nbfs_put_page(cp_page_1, 1);
	return NULL;
}

int nbfs_get_valid_checkpoint(struct nbfs_sb_info *sbi)
{
	struct nbfs_checkpoint *cp_block;
	struct nbfs_super_block *fsb = sbi->raw_super;
	struct page *cp1, *cp2, *cur_page;
	unsigned long blk_size = sbi->blocksize;
	unsigned long long cp1_version = 0, cp2_version = 0;
	unsigned long long cp_start_blk_no;
	unsigned int cp_blks = 1 + __cp_payload(sbi);
	block_t cp_blk_no;
	int i;

	sbi->ckpt = nbfs_kzalloc(sbi, array_size(blk_size, cp_blks),
				 GFP_KERNEL);
	if (!sbi->ckpt)
		return -ENOMEM;
	/*
	 * Finding out valid cp block involves read both
	 * sets( cp pack1 and cp pack 2)
	 */
	cp_start_blk_no = le32_to_cpu(fsb->cp_blkaddr);
	cp1 = validate_checkpoint(sbi, cp_start_blk_no, &cp1_version);

	/* The second checkpoint pack should start at the next segment */
	cp_start_blk_no += ((unsigned long long)1) <<
				le32_to_cpu(fsb->log_blocks_per_seg);
	cp2 = validate_checkpoint(sbi, cp_start_blk_no, &cp2_version);

	if (cp1 && cp2) {
		if (ver_after(cp2_version, cp1_version))
			cur_page = cp2;
		else
			cur_page = cp1;
	} else if (cp1) {
		cur_page = cp1;
	} else if (cp2) {
		cur_page = cp2;
	} else {
		goto fail_no_cp;
	}

	cp_block = (struct nbfs_checkpoint *)page_address(cur_page);
	memcpy(sbi->ckpt, cp_block, blk_size);

	if (cur_page == cp1)
		sbi->cur_cp_pack = 1;
	else
		sbi->cur_cp_pack = 2;

	/* Sanity checking of checkpoint */
	if (nbfs_sanity_check_ckpt(sbi))
		goto free_fail_no_cp;

	if (cp_blks <= 1)
		goto done;

	cp_blk_no = le32_to_cpu(fsb->cp_blkaddr);
	if (cur_page == cp2)
		cp_blk_no += 1 << le32_to_cpu(fsb->log_blocks_per_seg);

	for (i = 1; i < cp_blks; i++) {
		void *sit_bitmap_ptr;
		unsigned char *ckpt = (unsigned char *)sbi->ckpt;

		cur_page = nbfs_get_meta_page(sbi, cp_blk_no + i);
		if (IS_ERR(cur_page))
			goto free_fail_no_cp;
		sit_bitmap_ptr = page_address(cur_page);
		memcpy(ckpt + i * blk_size, sit_bitmap_ptr, blk_size);
		nbfs_put_page(cur_page, 1);
	}
done:
	nbfs_put_page(cp1, 1);
	nbfs_put_page(cp2, 1);
	return 0;

free_fail_no_cp:
	nbfs_put_page(cp1, 1);
	nbfs_put_page(cp2, 1);
fail_no_cp:
	kvfree(sbi->ckpt);
	return -EINVAL;
}

static void __add_dirty_inode(struct inode *inode, enum inode_type type)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	int flag = (type == DIR_INODE) ? FI_DIRTY_DIR : FI_DIRTY_FILE;

	if (is_inode_flag_set(inode, flag))
		return;

	set_inode_flag(inode, flag);
	if (!nbfs_is_volatile_file(inode))
		list_add_tail(&NBFS_I(inode)->dirty_list,
						&sbi->inode_list[type]);
	stat_inc_dirty_inode(sbi, type);
}

static void __remove_dirty_inode(struct inode *inode, enum inode_type type)
{
	int flag = (type == DIR_INODE) ? FI_DIRTY_DIR : FI_DIRTY_FILE;

	if (get_dirty_pages(inode) || !is_inode_flag_set(inode, flag))
		return;

	list_del_init(&NBFS_I(inode)->dirty_list);
	clear_inode_flag(inode, flag);
	stat_dec_dirty_inode(NBFS_I_SB(inode), type);
}

void nbfs_update_dirty_page(struct inode *inode, struct page *page)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	enum inode_type type = S_ISDIR(inode->i_mode) ? DIR_INODE : FILE_INODE;

	if (!S_ISDIR(inode->i_mode) && !S_ISREG(inode->i_mode) &&
			!S_ISLNK(inode->i_mode))
		return;

	spin_lock(&sbi->inode_lock[type]);
	if (type != FILE_INODE || test_opt(sbi, DATA_FLUSH))
		__add_dirty_inode(inode, type);
	inode_inc_dirty_pages(inode);
	spin_unlock(&sbi->inode_lock[type]);

	nbfs_set_page_private(page, 0);
	nbfs_trace_pid(page);
}

void nbfs_remove_dirty_inode(struct inode *inode)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	enum inode_type type = S_ISDIR(inode->i_mode) ? DIR_INODE : FILE_INODE;

	if (!S_ISDIR(inode->i_mode) && !S_ISREG(inode->i_mode) &&
			!S_ISLNK(inode->i_mode))
		return;

	if (type == FILE_INODE && !test_opt(sbi, DATA_FLUSH))
		return;

	spin_lock(&sbi->inode_lock[type]);
	__remove_dirty_inode(inode, type);
	spin_unlock(&sbi->inode_lock[type]);
}

int nbfs_sync_dirty_inodes(struct nbfs_sb_info *sbi, enum inode_type type)
{
	struct list_head *head;
	struct inode *inode;
	struct nbfs_inode_info *fi;
	bool is_dir = (type == DIR_INODE);
	unsigned long ino = 0;

	trace_nbfs_sync_dirty_inodes_enter(sbi->sb, is_dir,
				get_pages(sbi, is_dir ?
				NBFS_DIRTY_DENTS : NBFS_DIRTY_DATA));
retry:
	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;

	spin_lock(&sbi->inode_lock[type]);

	head = &sbi->inode_list[type];
	if (list_empty(head)) {
		spin_unlock(&sbi->inode_lock[type]);
		trace_nbfs_sync_dirty_inodes_exit(sbi->sb, is_dir,
				get_pages(sbi, is_dir ?
				NBFS_DIRTY_DENTS : NBFS_DIRTY_DATA));
		return 0;
	}
	fi = list_first_entry(head, struct nbfs_inode_info, dirty_list);
	inode = igrab(&fi->vfs_inode);
	spin_unlock(&sbi->inode_lock[type]);
	if (inode) {
		unsigned long cur_ino = inode->i_ino;

		if (is_dir)
			NBFS_I(inode)->cp_task = current;

		filemap_fdatawrite(inode->i_mapping);

		if (is_dir)
			NBFS_I(inode)->cp_task = NULL;

		iput(inode);
		/* We need to give cpu to another writers. */
		if (ino == cur_ino)
			cond_resched();
		else
			ino = cur_ino;
	} else {
		/*
		 * We should submit bio, since it exists several
		 * wribacking dentry pages in the freeing inode.
		 */
		nbfs_submit_merged_write(sbi, DATA);
		cond_resched();
	}
	goto retry;
}

int nbfs_sync_inode_meta(struct nbfs_sb_info *sbi)
{
	struct list_head *head = &sbi->inode_list[DIRTY_META];
	struct inode *inode;
	struct nbfs_inode_info *fi;
	s64 total = get_pages(sbi, NBFS_DIRTY_IMETA);

	while (total--) {
		if (unlikely(nbfs_cp_error(sbi)))
			return -EIO;

		spin_lock(&sbi->inode_lock[DIRTY_META]);
		if (list_empty(head)) {
			spin_unlock(&sbi->inode_lock[DIRTY_META]);
			return 0;
		}
		fi = list_first_entry(head, struct nbfs_inode_info,
							gdirty_list);
		inode = igrab(&fi->vfs_inode);
		spin_unlock(&sbi->inode_lock[DIRTY_META]);
		if (inode) {
			sync_inode_metadata(inode, 0);

			/* it's on eviction */
			if (is_inode_flag_set(inode, FI_DIRTY_INODE))
				nbfs_update_inode_page(inode);
			iput(inode);
		}
	}
	return 0;
}

static void __prepare_cp_block(struct nbfs_sb_info *sbi)
{
	struct nbfs_checkpoint *ckpt = NBFS_CKPT(sbi);
	struct nbfs_nm_info *nm_i = NM_I(sbi);
	nid_t last_nid = nm_i->next_scan_nid;

	next_free_nid(sbi, &last_nid);
	ckpt->valid_block_count = cpu_to_le64(valid_user_blocks(sbi));
	ckpt->valid_node_count = cpu_to_le32(valid_node_count(sbi));
	ckpt->valid_inode_count = cpu_to_le32(valid_inode_count(sbi));
	ckpt->next_free_nid = cpu_to_le32(last_nid);
}

static bool __need_flush_quota(struct nbfs_sb_info *sbi)
{
	if (!is_journalled_quota(sbi))
		return false;
	if (is_sbi_flag_set(sbi, SBI_QUOTA_SKIP_FLUSH))
		return false;
	if (is_sbi_flag_set(sbi, SBI_QUOTA_NEED_REPAIR))
		return false;
	if (is_sbi_flag_set(sbi, SBI_QUOTA_NEED_FLUSH))
		return true;
	if (get_pages(sbi, NBFS_DIRTY_QDATA))
		return true;
	return false;
}

/*
 * Freeze all the FS-operations for checkpoint.
 */
static int block_operations(struct nbfs_sb_info *sbi)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = LONG_MAX,
		.for_reclaim = 0,
	};
	struct blk_plug plug;
	int err = 0, cnt = 0;

	blk_start_plug(&plug);

retry_flush_quotas:
	if (__need_flush_quota(sbi)) {
		int locked;

		if (++cnt > DEFAULT_RETRY_QUOTA_FLUSH_COUNT) {
			set_sbi_flag(sbi, SBI_QUOTA_SKIP_FLUSH);
			nbfs_lock_all(sbi);
			goto retry_flush_dents;
		}
		clear_sbi_flag(sbi, SBI_QUOTA_NEED_FLUSH);

		/* only failed during mount/umount/freeze/quotactl */
		locked = down_read_trylock(&sbi->sb->s_umount);
		nbfs_quota_sync(sbi->sb, -1);
		if (locked)
			up_read(&sbi->sb->s_umount);
	}

	nbfs_lock_all(sbi);
	if (__need_flush_quota(sbi)) {
		nbfs_unlock_all(sbi);
		cond_resched();
		goto retry_flush_quotas;
	}

retry_flush_dents:
	/* write all the dirty dentry pages */
	if (get_pages(sbi, NBFS_DIRTY_DENTS)) {
		nbfs_unlock_all(sbi);
		err = nbfs_sync_dirty_inodes(sbi, DIR_INODE);
		if (err)
			goto out;
		cond_resched();
		goto retry_flush_quotas;
	}

	/*
	 * POR: we should ensure that there are no dirty node pages
	 * until finishing nat/sit flush. inode->i_blocks can be updated.
	 */
	down_write(&sbi->node_change);

	if (__need_flush_quota(sbi)) {
		up_write(&sbi->node_change);
		nbfs_unlock_all(sbi);
		goto retry_flush_quotas;
	}

	if (get_pages(sbi, NBFS_DIRTY_IMETA)) {
		up_write(&sbi->node_change);
		nbfs_unlock_all(sbi);
		err = nbfs_sync_inode_meta(sbi);
		if (err)
			goto out;
		cond_resched();
		goto retry_flush_quotas;
	}

retry_flush_nodes:
	down_write(&sbi->node_write);

	if (get_pages(sbi, NBFS_DIRTY_NODES)) {
		up_write(&sbi->node_write);
		atomic_inc(&sbi->wb_sync_req[NODE]);
		err = nbfs_sync_node_pages(sbi, &wbc, false, FS_CP_NODE_IO);
		atomic_dec(&sbi->wb_sync_req[NODE]);
		if (err) {
			up_write(&sbi->node_change);
			nbfs_unlock_all(sbi);
			goto out;
		}
		cond_resched();
		goto retry_flush_nodes;
	}

	/*
	 * sbi->node_change is used only for AIO write_begin path which produces
	 * dirty node blocks and some checkpoint values by block allocation.
	 */
	__prepare_cp_block(sbi);
	up_write(&sbi->node_change);
out:
	blk_finish_plug(&plug);
	return err;
}

static void unblock_operations(struct nbfs_sb_info *sbi)
{
	up_write(&sbi->node_write);
	nbfs_unlock_all(sbi);
}

void nbfs_wait_on_all_pages_writeback(struct nbfs_sb_info *sbi)
{
	DEFINE_WAIT(wait);

	for (;;) {
		prepare_to_wait(&sbi->cp_wait, &wait, TASK_UNINTERRUPTIBLE);

		if (!get_pages(sbi, NBFS_WB_CP_DATA))
			break;

		if (unlikely(nbfs_cp_error(sbi)))
			break;

		io_schedule_timeout(5*HZ);
	}
	finish_wait(&sbi->cp_wait, &wait);
}

static void update_ckpt_flags(struct nbfs_sb_info *sbi, struct cp_control *cpc)
{
	unsigned long orphan_num = sbi->im[ORPHAN_INO].ino_num;
	struct nbfs_checkpoint *ckpt = NBFS_CKPT(sbi);
	unsigned long flags;

	spin_lock_irqsave(&sbi->cp_lock, flags);

	if ((cpc->reason & CP_UMOUNT) &&
			le32_to_cpu(ckpt->cp_pack_total_block_count) >
			sbi->blocks_per_seg - NM_I(sbi)->nat_bits_blocks)
		disable_nat_bits(sbi, false);

	if (cpc->reason & CP_TRIMMED)
		__set_ckpt_flags(ckpt, CP_TRIMMED_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_TRIMMED_FLAG);

	if (cpc->reason & CP_UMOUNT)
		__set_ckpt_flags(ckpt, CP_UMOUNT_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_UMOUNT_FLAG);

	if (cpc->reason & CP_FASTBOOT)
		__set_ckpt_flags(ckpt, CP_FASTBOOT_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_FASTBOOT_FLAG);

	if (orphan_num)
		__set_ckpt_flags(ckpt, CP_ORPHAN_PRESENT_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_ORPHAN_PRESENT_FLAG);

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK))
		__set_ckpt_flags(ckpt, CP_FSCK_FLAG);

	if (is_sbi_flag_set(sbi, SBI_CP_DISABLED))
		__set_ckpt_flags(ckpt, CP_DISABLED_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_DISABLED_FLAG);

	if (is_sbi_flag_set(sbi, SBI_CP_DISABLED_QUICK))
		__set_ckpt_flags(ckpt, CP_DISABLED_QUICK_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_DISABLED_QUICK_FLAG);

	if (is_sbi_flag_set(sbi, SBI_QUOTA_SKIP_FLUSH))
		__set_ckpt_flags(ckpt, CP_QUOTA_NEED_FSCK_FLAG);
	/*
	 * TODO: we count on fsck.nbfs to clear this flag until we figure out
	 * missing cases which clear it incorrectly.
	 */

	if (is_sbi_flag_set(sbi, SBI_QUOTA_NEED_REPAIR))
		__set_ckpt_flags(ckpt, CP_QUOTA_NEED_FSCK_FLAG);

	/* set this flag to activate crc|cp_ver for recovery */
	__set_ckpt_flags(ckpt, CP_CRC_RECOVERY_FLAG);
	__clear_ckpt_flags(ckpt, CP_NOCRC_RECOVERY_FLAG);

	spin_unlock_irqrestore(&sbi->cp_lock, flags);
}

static void commit_checkpoint(struct nbfs_sb_info *sbi,
	void *src, block_t blk_addr)
{
	struct writeback_control wbc = {
		.for_reclaim = 0,
	};

	/*
	 * pagevec_lookup_tag and lock_page again will take
	 * some extra time. Therefore, nbfs_update_meta_pages and
	 * nbfs_sync_meta_pages are combined in this function.
	 */
	struct page *page = nbfs_grab_meta_page(sbi, blk_addr);
	int err;

	nbfs_wait_on_page_writeback(page, META, true, true);

	memcpy(page_address(page), src, PAGE_SIZE);

	set_page_dirty(page);
	if (unlikely(!clear_page_dirty_for_io(page)))
		nbfs_bug_on(sbi, 1);

	/* writeout cp pack 2 page */
	err = __nbfs_write_meta_page(page, &wbc, FS_CP_META_IO);
	if (unlikely(err && nbfs_cp_error(sbi))) {
		nbfs_put_page(page, 1);
		return;
	}

	nbfs_bug_on(sbi, err);
	nbfs_put_page(page, 0);

	/* submit checkpoint (with barrier if NOBARRIER is not set) */
	nbfs_submit_merged_write(sbi, META_FLUSH);
}

static int do_checkpoint(struct nbfs_sb_info *sbi, struct cp_control *cpc)
{
	struct nbfs_checkpoint *ckpt = NBFS_CKPT(sbi);
	struct nbfs_nm_info *nm_i = NM_I(sbi);
	unsigned long orphan_num = sbi->im[ORPHAN_INO].ino_num, flags;
	block_t start_blk;
	unsigned int data_sum_blocks, orphan_blocks;
	__u32 crc32 = 0;
	int i;
	int cp_payload_blks = __cp_payload(sbi);
	struct super_block *sb = sbi->sb;
	struct curseg_info *seg_i = CURSEG_I(sbi, CURSEG_HOT_NODE);
	u64 kbytes_written;
	int err;

	/* Flush all the NAT/SIT pages */
	nbfs_sync_meta_pages(sbi, META, LONG_MAX, FS_CP_META_IO);
	nbfs_bug_on(sbi, get_pages(sbi, NBFS_DIRTY_META) &&
					!nbfs_cp_error(sbi));

	/*
	 * modify checkpoint
	 * version number is already updated
	 */
	ckpt->elapsed_time = cpu_to_le64(get_mtime(sbi, true));
	ckpt->free_segment_count = cpu_to_le32(free_segments(sbi));
	for (i = 0; i < NR_CURSEG_NODE_TYPE; i++) {
		ckpt->cur_node_segno[i] =
			cpu_to_le32(curseg_segno(sbi, i + CURSEG_HOT_NODE));
		ckpt->cur_node_blkoff[i] =
			cpu_to_le16(curseg_blkoff(sbi, i + CURSEG_HOT_NODE));
		ckpt->alloc_type[i + CURSEG_HOT_NODE] =
				curseg_alloc_type(sbi, i + CURSEG_HOT_NODE);
	}
	for (i = 0; i < NR_CURSEG_DATA_TYPE; i++) {
		ckpt->cur_data_segno[i] =
			cpu_to_le32(curseg_segno(sbi, i + CURSEG_HOT_DATA));
		ckpt->cur_data_blkoff[i] =
			cpu_to_le16(curseg_blkoff(sbi, i + CURSEG_HOT_DATA));
		ckpt->alloc_type[i + CURSEG_HOT_DATA] =
				curseg_alloc_type(sbi, i + CURSEG_HOT_DATA);
	}

	/* 2 cp  + n data seg summary + orphan inode blocks */
	data_sum_blocks = nbfs_npages_for_summary_flush(sbi, false);
	spin_lock_irqsave(&sbi->cp_lock, flags);
	if (data_sum_blocks < NR_CURSEG_DATA_TYPE)
		__set_ckpt_flags(ckpt, CP_COMPACT_SUM_FLAG);
	else
		__clear_ckpt_flags(ckpt, CP_COMPACT_SUM_FLAG);
	spin_unlock_irqrestore(&sbi->cp_lock, flags);

	orphan_blocks = GET_ORPHAN_BLOCKS(orphan_num);
	ckpt->cp_pack_start_sum = cpu_to_le32(1 + cp_payload_blks +
			orphan_blocks);

	if (__remain_node_summaries(cpc->reason))
		ckpt->cp_pack_total_block_count = cpu_to_le32(NBFS_CP_PACKS+
				cp_payload_blks + data_sum_blocks +
				orphan_blocks + NR_CURSEG_NODE_TYPE);
	else
		ckpt->cp_pack_total_block_count = cpu_to_le32(NBFS_CP_PACKS +
				cp_payload_blks + data_sum_blocks +
				orphan_blocks);

	/* update ckpt flag for checkpoint */
	update_ckpt_flags(sbi, cpc);

	/* update SIT/NAT bitmap */
	get_sit_bitmap(sbi, __bitmap_ptr(sbi, SIT_BITMAP));
	get_nat_bitmap(sbi, __bitmap_ptr(sbi, NAT_BITMAP));

	crc32 = nbfs_crc32(sbi, ckpt, le32_to_cpu(ckpt->checksum_offset));
	*((__le32 *)((unsigned char *)ckpt +
				le32_to_cpu(ckpt->checksum_offset)))
				= cpu_to_le32(crc32);

	start_blk = __start_cp_next_addr(sbi);

	/* write nat bits */
	if (enabled_nat_bits(sbi, cpc)) {
		__u64 cp_ver = cur_cp_version(ckpt);
		block_t blk;

		cp_ver |= ((__u64)crc32 << 32);
		*(__le64 *)nm_i->nat_bits = cpu_to_le64(cp_ver);

		blk = start_blk + sbi->blocks_per_seg - nm_i->nat_bits_blocks;
		for (i = 0; i < nm_i->nat_bits_blocks; i++)
			nbfs_update_meta_page(sbi, nm_i->nat_bits +
					(i << NBFS_BLKSIZE_BITS), blk + i);
	}

	/* write out checkpoint buffer at block 0 */
	nbfs_update_meta_page(sbi, ckpt, start_blk++);

	for (i = 1; i < 1 + cp_payload_blks; i++)
		nbfs_update_meta_page(sbi, (char *)ckpt + i * NBFS_BLKSIZE,
							start_blk++);

	if (orphan_num) {
		write_orphan_inodes(sbi, start_blk);
		start_blk += orphan_blocks;
	}

	nbfs_write_data_summaries(sbi, start_blk);
	start_blk += data_sum_blocks;

	/* Record write statistics in the hot node summary */
	kbytes_written = sbi->kbytes_written;
	if (sb->s_bdev->bd_part)
		kbytes_written += BD_PART_WRITTEN(sbi);

	seg_i->journal->info.kbytes_written = cpu_to_le64(kbytes_written);

	if (__remain_node_summaries(cpc->reason)) {
		nbfs_write_node_summaries(sbi, start_blk);
		start_blk += NR_CURSEG_NODE_TYPE;
	}

	/* update user_block_counts */
	sbi->last_valid_block_count = sbi->total_valid_block_count;
	percpu_counter_set(&sbi->alloc_valid_block_count, 0);

	/* Here, we have one bio having CP pack except cp pack 2 page */
	nbfs_sync_meta_pages(sbi, META, LONG_MAX, FS_CP_META_IO);
	nbfs_bug_on(sbi, get_pages(sbi, NBFS_DIRTY_META) &&
					!nbfs_cp_error(sbi));

	/* wait for previous submitted meta pages writeback */
	nbfs_wait_on_all_pages_writeback(sbi);

	/* flush all device cache */
	err = nbfs_flush_device_cache(sbi);
	if (err)
		return err;

	/* barrier and flush checkpoint cp pack 2 page if it can */
	commit_checkpoint(sbi, ckpt, start_blk);
	nbfs_wait_on_all_pages_writeback(sbi);

	/*
	 * invalidate intermediate page cache borrowed from meta inode
	 * which are used for migration of encrypted inode's blocks.
	 */
	if (nbfs_sb_has_encrypt(sbi))
		invalidate_mapping_pages(META_MAPPING(sbi),
				MAIN_BLKADDR(sbi), MAX_BLKADDR(sbi) - 1);

	nbfs_release_ino_entry(sbi, false);

	nbfs_reset_fsync_node_info(sbi);

	clear_sbi_flag(sbi, SBI_IS_DIRTY);
	clear_sbi_flag(sbi, SBI_NEED_CP);
	clear_sbi_flag(sbi, SBI_QUOTA_SKIP_FLUSH);
	sbi->unusable_block_count = 0;
	__set_cp_next_pack(sbi);

	/*
	 * redirty superblock if metadata like node page or inode cache is
	 * updated during writing checkpoint.
	 */
	if (get_pages(sbi, NBFS_DIRTY_NODES) ||
			get_pages(sbi, NBFS_DIRTY_IMETA))
		set_sbi_flag(sbi, SBI_IS_DIRTY);

	nbfs_bug_on(sbi, get_pages(sbi, NBFS_DIRTY_DENTS));

	return unlikely(nbfs_cp_error(sbi)) ? -EIO : 0;
}

/*
 * We guarantee that this checkpoint procedure will not fail.
 */
int nbfs_write_checkpoint(struct nbfs_sb_info *sbi, struct cp_control *cpc)
{
	struct nbfs_checkpoint *ckpt = NBFS_CKPT(sbi);
	unsigned long long ckpt_ver;
	int err = 0;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		if (cpc->reason != CP_PAUSE)
			return 0;
		nbfs_msg(sbi->sb, KERN_WARNING,
				"Start checkpoint disabled!");
	}
	mutex_lock(&sbi->cp_mutex);

	if (!is_sbi_flag_set(sbi, SBI_IS_DIRTY) &&
		((cpc->reason & CP_FASTBOOT) || (cpc->reason & CP_SYNC) ||
		((cpc->reason & CP_DISCARD) && !sbi->discard_blks)))
		goto out;
	if (unlikely(nbfs_cp_error(sbi))) {
		err = -EIO;
		goto out;
	}
	if (nbfs_readonly(sbi->sb)) {
		err = -EROFS;
		goto out;
	}

	trace_nbfs_write_checkpoint(sbi->sb, cpc->reason, "start block_ops");

	err = block_operations(sbi);
	if (err)
		goto out;

	trace_nbfs_write_checkpoint(sbi->sb, cpc->reason, "finish block_ops");

	nbfs_flush_merged_writes(sbi);

	/* this is the case of multiple fstrims without any changes */
	if (cpc->reason & CP_DISCARD) {
		if (!nbfs_exist_trim_candidates(sbi, cpc)) {
			unblock_operations(sbi);
			goto out;
		}

		if (NM_I(sbi)->dirty_nat_cnt == 0 &&
				SIT_I(sbi)->dirty_sentries == 0 &&
				prefree_segments(sbi) == 0) {
			nbfs_flush_sit_entries(sbi, cpc);
			nbfs_clear_prefree_segments(sbi, cpc);
			unblock_operations(sbi);
			goto out;
		}
	}

	/*
	 * update checkpoint pack index
	 * Increase the version number so that
	 * SIT entries and seg summaries are written at correct place
	 */
	ckpt_ver = cur_cp_version(ckpt);
	ckpt->checkpoint_ver = cpu_to_le64(++ckpt_ver);

	/* write cached NAT/SIT entries to NAT/SIT area */
	err = nbfs_flush_nat_entries(sbi, cpc);
	if (err)
		goto stop;

	nbfs_flush_sit_entries(sbi, cpc);

	/* unlock all the fs_lock[] in do_checkpoint() */
	err = do_checkpoint(sbi, cpc);
	if (err)
		nbfs_release_discard_addrs(sbi);
	else
		nbfs_clear_prefree_segments(sbi, cpc);
stop:
	unblock_operations(sbi);
	stat_inc_cp_count(sbi->stat_info);

	if (cpc->reason & CP_RECOVERY)
		nbfs_msg(sbi->sb, KERN_NOTICE,
			"checkpoint: version = %llx", ckpt_ver);

	/* do checkpoint periodically */
	nbfs_update_time(sbi, CP_TIME);
	trace_nbfs_write_checkpoint(sbi->sb, cpc->reason, "finish checkpoint");
out:
	mutex_unlock(&sbi->cp_mutex);
	return err;
}

void nbfs_init_ino_entry_info(struct nbfs_sb_info *sbi)
{
	int i;

	for (i = 0; i < MAX_INO_ENTRY; i++) {
		struct inode_management *im = &sbi->im[i];

		INIT_RADIX_TREE(&im->ino_root, GFP_ATOMIC);
		spin_lock_init(&im->ino_lock);
		INIT_LIST_HEAD(&im->ino_list);
		im->ino_num = 0;
	}

	sbi->max_orphans = (sbi->blocks_per_seg - NBFS_CP_PACKS -
			NR_CURSEG_TYPE - __cp_payload(sbi)) *
				NBFS_ORPHANS_PER_BLOCK;
}

int __init nbfs_create_checkpoint_caches(void)
{
	ino_entry_slab = nbfs_kmem_cache_create("nbfs_ino_entry",
			sizeof(struct ino_entry));
	if (!ino_entry_slab)
		return -ENOMEM;
	nbfs_inode_entry_slab = nbfs_kmem_cache_create("nbfs_inode_entry",
			sizeof(struct inode_entry));
	if (!nbfs_inode_entry_slab) {
		kmem_cache_destroy(ino_entry_slab);
		return -ENOMEM;
	}
	return 0;
}

void nbfs_destroy_checkpoint_caches(void)
{
	kmem_cache_destroy(ino_entry_slab);
	kmem_cache_destroy(nbfs_inode_entry_slab);
}
