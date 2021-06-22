// SPDX-License-Identifier: GPL-2.0
/*
 * fs/nbfs/dir.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/nbfs_fs.h>
#include <linux/sched/signal.h>
#include "nbfs.h"
#include "node.h"
#include "acl.h"
#include "xattr.h"
#include <trace/events/nbfs.h>

static unsigned long dir_blocks(struct inode *inode)
{
	return ((unsigned long long) (i_size_read(inode) + PAGE_SIZE - 1))
							>> PAGE_SHIFT;
}

static unsigned int dir_buckets(unsigned int level, int dir_level)
{
	if (level + dir_level < MAX_DIR_HASH_DEPTH / 2)
		return 1 << (level + dir_level);
	else
		return MAX_DIR_BUCKETS;
}

static unsigned int bucket_blocks(unsigned int level)
{
	if (level < MAX_DIR_HASH_DEPTH / 2)
		return 2;
	else
		return 4;
}

static unsigned char nbfs_filetype_table[NBFS_FT_MAX] = {
	[NBFS_FT_UNKNOWN]	= DT_UNKNOWN,
	[NBFS_FT_REG_FILE]	= DT_REG,
	[NBFS_FT_DIR]		= DT_DIR,
	[NBFS_FT_CHRDEV]	= DT_CHR,
	[NBFS_FT_BLKDEV]	= DT_BLK,
	[NBFS_FT_FIFO]		= DT_FIFO,
	[NBFS_FT_SOCK]		= DT_SOCK,
	[NBFS_FT_SYMLINK]	= DT_LNK,
};

static unsigned char nbfs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= NBFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= NBFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= NBFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= NBFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= NBFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= NBFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= NBFS_FT_SYMLINK,
};

static void set_de_type(struct nbfs_dir_entry *de, umode_t mode)
{
	de->file_type = nbfs_type_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

unsigned char nbfs_get_de_type(struct nbfs_dir_entry *de)
{
	if (de->file_type < NBFS_FT_MAX)
		return nbfs_filetype_table[de->file_type];
	return DT_UNKNOWN;
}

static unsigned long dir_block_index(unsigned int level,
				int dir_level, unsigned int idx)
{
	unsigned long i;
	unsigned long bidx = 0;

	for (i = 0; i < level; i++)
		bidx += dir_buckets(i, dir_level) * bucket_blocks(i);
	bidx += idx * bucket_blocks(level);
	return bidx;
}

static struct nbfs_dir_entry *find_in_block(struct page *dentry_page,
				struct fscrypt_name *fname,
				nbfs_hash_t namehash,
				int *max_slots,
				struct page **res_page)
{
	struct nbfs_dentry_block *dentry_blk;
	struct nbfs_dir_entry *de;
	struct nbfs_dentry_ptr d;

	dentry_blk = (struct nbfs_dentry_block *)page_address(dentry_page);

	make_dentry_ptr_block(NULL, &d, dentry_blk);
	de = nbfs_find_target_dentry(fname, namehash, max_slots, &d);
	if (de)
		*res_page = dentry_page;

	return de;
}

struct nbfs_dir_entry *nbfs_find_target_dentry(struct fscrypt_name *fname,
			nbfs_hash_t namehash, int *max_slots,
			struct nbfs_dentry_ptr *d)
{
	struct nbfs_dir_entry *de;
	unsigned long bit_pos = 0;
	int max_len = 0;

	if (max_slots)
		*max_slots = 0;
	while (bit_pos < d->max) {
		if (!test_bit_le(bit_pos, d->bitmap)) {
			bit_pos++;
			max_len++;
			continue;
		}

		de = &d->dentry[bit_pos];

		if (unlikely(!de->name_len)) {
			bit_pos++;
			continue;
		}

		if (de->hash_code == namehash &&
		    fscrypt_match_name(fname, d->filename[bit_pos],
				       le16_to_cpu(de->name_len)))
			goto found;

		if (max_slots && max_len > *max_slots)
			*max_slots = max_len;
		max_len = 0;

		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
	}

	de = NULL;
found:
	if (max_slots && max_len > *max_slots)
		*max_slots = max_len;
	return de;
}

static struct nbfs_dir_entry *find_in_level(struct inode *dir,
					unsigned int level,
					struct fscrypt_name *fname,
					struct page **res_page)
{
	struct qstr name = FSTR_TO_QSTR(&fname->disk_name);
	int s = GET_DENTRY_SLOTS(name.len);
	unsigned int nbucket, nblock;
	unsigned int bidx, end_block;
	struct page *dentry_page;
	struct nbfs_dir_entry *de = NULL;
	bool room = false;
	int max_slots;
	nbfs_hash_t namehash = nbfs_dentry_hash(&name, fname);

	nbucket = dir_buckets(level, NBFS_I(dir)->i_dir_level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, NBFS_I(dir)->i_dir_level,
					le32_to_cpu(namehash) % nbucket);
	end_block = bidx + nblock;

	for (; bidx < end_block; bidx++) {
		/* no need to allocate new dentry pages to all the indices */
		dentry_page = nbfs_find_data_page(dir, bidx);
		if (IS_ERR(dentry_page)) {
			if (PTR_ERR(dentry_page) == -ENOENT) {
				room = true;
				continue;
			} else {
				*res_page = dentry_page;
				break;
			}
		}

		de = find_in_block(dentry_page, fname, namehash, &max_slots,
								res_page);
		if (de)
			break;

		if (max_slots >= s)
			room = true;
		nbfs_put_page(dentry_page, 0);
	}

	if (!de && room && NBFS_I(dir)->chash != namehash) {
		NBFS_I(dir)->chash = namehash;
		NBFS_I(dir)->clevel = level;
	}

	return de;
}

struct nbfs_dir_entry *__nbfs_find_entry(struct inode *dir,
			struct fscrypt_name *fname, struct page **res_page)
{
	unsigned long npages = dir_blocks(dir);
	struct nbfs_dir_entry *de = NULL;
	unsigned int max_depth;
	unsigned int level;

	if (nbfs_has_inline_dentry(dir)) {
		*res_page = NULL;
		de = nbfs_find_in_inline_dir(dir, fname, res_page);
		goto out;
	}

	if (npages == 0) {
		*res_page = NULL;
		goto out;
	}

	max_depth = NBFS_I(dir)->i_current_depth;
	if (unlikely(max_depth > MAX_DIR_HASH_DEPTH)) {
		nbfs_msg(NBFS_I_SB(dir)->sb, KERN_WARNING,
				"Corrupted max_depth of %lu: %u",
				dir->i_ino, max_depth);
		max_depth = MAX_DIR_HASH_DEPTH;
		nbfs_i_depth_write(dir, max_depth);
	}

	for (level = 0; level < max_depth; level++) {
		*res_page = NULL;
		de = find_in_level(dir, level, fname, res_page);
		if (de || IS_ERR(*res_page))
			break;
	}
out:
	/* This is to increase the speed of nbfs_create */
	if (!de)
		NBFS_I(dir)->task = current;
	return de;
}

/*
 * Find an entry in the specified directory with the wanted name.
 * It returns the page where the entry was found (as a parameter - res_page),
 * and the entry itself. Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */
struct nbfs_dir_entry *nbfs_find_entry(struct inode *dir,
			const struct qstr *child, struct page **res_page)
{
	struct nbfs_dir_entry *de = NULL;
	struct fscrypt_name fname;
	int err;

	err = fscrypt_setup_filename(dir, child, 1, &fname);
	if (err) {
		if (err == -ENOENT)
			*res_page = NULL;
		else
			*res_page = ERR_PTR(err);
		return NULL;
	}

	de = __nbfs_find_entry(dir, &fname, res_page);

	fscrypt_free_filename(&fname);
	return de;
}

struct nbfs_dir_entry *nbfs_parent_dir(struct inode *dir, struct page **p)
{
	struct qstr dotdot = QSTR_INIT("..", 2);

	return nbfs_find_entry(dir, &dotdot, p);
}

ino_t nbfs_inode_by_name(struct inode *dir, const struct qstr *qstr,
							struct page **page)
{
	ino_t res = 0;
	struct nbfs_dir_entry *de;

	de = nbfs_find_entry(dir, qstr, page);
	if (de) {
		res = le32_to_cpu(de->ino);
		nbfs_put_page(*page, 0);
	}

	return res;
}

void nbfs_set_link(struct inode *dir, struct nbfs_dir_entry *de,
		struct page *page, struct inode *inode)
{
	enum page_type type = nbfs_has_inline_dentry(dir) ? NODE : DATA;
	lock_page(page);
	nbfs_wait_on_page_writeback(page, type, true, true);
	de->ino = cpu_to_le32(inode->i_ino);
	set_de_type(de, inode->i_mode);
	set_page_dirty(page);

	dir->i_mtime = dir->i_ctime = current_time(dir);
	nbfs_mark_inode_dirty_sync(dir, false);
	nbfs_put_page(page, 1);
}

static void init_dent_inode(const struct qstr *name, struct page *ipage)
{
	struct nbfs_inode *ri;

	nbfs_wait_on_page_writeback(ipage, NODE, true, true);

	/* copy name info. to this inode page */
	ri = NBFS_INODE(ipage);
	ri->i_namelen = cpu_to_le32(name->len);
	memcpy(ri->i_name, name->name, name->len);
	set_page_dirty(ipage);
}

void nbfs_do_make_empty_dir(struct inode *inode, struct inode *parent,
					struct nbfs_dentry_ptr *d)
{
	struct qstr dot = QSTR_INIT(".", 1);
	struct qstr dotdot = QSTR_INIT("..", 2);

	/* update dirent of "." */
	nbfs_update_dentry(inode->i_ino, inode->i_mode, d, &dot, 0, 0);

	/* update dirent of ".." */
	nbfs_update_dentry(parent->i_ino, parent->i_mode, d, &dotdot, 0, 1);
}

static int make_empty_dir(struct inode *inode,
		struct inode *parent, struct page *page)
{
	struct page *dentry_page;
	struct nbfs_dentry_block *dentry_blk;
	struct nbfs_dentry_ptr d;

	if (nbfs_has_inline_dentry(inode))
		return nbfs_make_empty_inline_dir(inode, parent, page);

	dentry_page = nbfs_get_new_data_page(inode, page, 0, true);
	if (IS_ERR(dentry_page))
		return PTR_ERR(dentry_page);

	dentry_blk = page_address(dentry_page);

	make_dentry_ptr_block(NULL, &d, dentry_blk);
	nbfs_do_make_empty_dir(inode, parent, &d);

	set_page_dirty(dentry_page);
	nbfs_put_page(dentry_page, 1);
	return 0;
}

struct page *nbfs_init_inode_metadata(struct inode *inode, struct inode *dir,
			const struct qstr *new_name, const struct qstr *orig_name,
			struct page *dpage)
{
	struct page *page;
	int dummy_encrypt = DUMMY_ENCRYPTION_ENABLED(NBFS_I_SB(dir));
	int err;

	if (is_inode_flag_set(inode, FI_NEW_INODE)) {
		page = nbfs_new_inode_page(inode);
		if (IS_ERR(page))
			return page;

		if (S_ISDIR(inode->i_mode)) {
			/* in order to handle error case */
			get_page(page);
			err = make_empty_dir(inode, dir, page);
			if (err) {
				lock_page(page);
				goto put_error;
			}
			put_page(page);
		}

		err = nbfs_init_acl(inode, dir, page, dpage);
		if (err)
			goto put_error;

		err = nbfs_init_security(inode, dir, orig_name, page);
		if (err)
			goto put_error;

		if ((IS_ENCRYPTED(dir) || dummy_encrypt) &&
					nbfs_may_encrypt(inode)) {
			err = fscrypt_inherit_context(dir, inode, page, false);
			if (err)
				goto put_error;
		}
	} else {
		page = nbfs_get_node_page(NBFS_I_SB(dir), inode->i_ino);
		if (IS_ERR(page))
			return page;
	}

	if (new_name) {
		init_dent_inode(new_name, page);
		if (IS_ENCRYPTED(dir))
			file_set_enc_name(inode);
	}

	/*
	 * This file should be checkpointed during fsync.
	 * We lost i_pino from now on.
	 */
	if (is_inode_flag_set(inode, FI_INC_LINK)) {
		if (!S_ISDIR(inode->i_mode))
			file_lost_pino(inode);
		/*
		 * If link the tmpfile to alias through linkat path,
		 * we should remove this inode from orphan list.
		 */
		if (inode->i_nlink == 0)
			nbfs_remove_orphan_inode(NBFS_I_SB(dir), inode->i_ino);
		nbfs_i_links_write(inode, true);
	}
	return page;

put_error:
	clear_nlink(inode);
	nbfs_update_inode(inode, page);
	nbfs_put_page(page, 1);
	return ERR_PTR(err);
}

void nbfs_update_parent_metadata(struct inode *dir, struct inode *inode,
						unsigned int current_depth)
{
	if (inode && is_inode_flag_set(inode, FI_NEW_INODE)) {
		if (S_ISDIR(inode->i_mode))
			nbfs_i_links_write(dir, true);
		clear_inode_flag(inode, FI_NEW_INODE);
	}
	dir->i_mtime = dir->i_ctime = current_time(dir);
	nbfs_mark_inode_dirty_sync(dir, false);

	if (NBFS_I(dir)->i_current_depth != current_depth)
		nbfs_i_depth_write(dir, current_depth);

	if (inode && is_inode_flag_set(inode, FI_INC_LINK))
		clear_inode_flag(inode, FI_INC_LINK);
}

int nbfs_room_for_filename(const void *bitmap, int slots, int max_slots)
{
	int bit_start = 0;
	int zero_start, zero_end;
next:
	zero_start = find_next_zero_bit_le(bitmap, max_slots, bit_start);
	if (zero_start >= max_slots)
		return max_slots;

	zero_end = find_next_bit_le(bitmap, max_slots, zero_start);
	if (zero_end - zero_start >= slots)
		return zero_start;

	bit_start = zero_end + 1;

	if (zero_end + 1 >= max_slots)
		return max_slots;
	goto next;
}

void nbfs_update_dentry(nid_t ino, umode_t mode, struct nbfs_dentry_ptr *d,
				const struct qstr *name, nbfs_hash_t name_hash,
				unsigned int bit_pos)
{
	struct nbfs_dir_entry *de;
	int slots = GET_DENTRY_SLOTS(name->len);
	int i;

	de = &d->dentry[bit_pos];
	de->hash_code = name_hash;
	de->name_len = cpu_to_le16(name->len);
	memcpy(d->filename[bit_pos], name->name, name->len);
	de->ino = cpu_to_le32(ino);
	set_de_type(de, mode);
	for (i = 0; i < slots; i++) {
		__set_bit_le(bit_pos + i, (void *)d->bitmap);
		/* avoid wrong garbage data for readdir */
		if (i)
			(de + i)->name_len = 0;
	}
}

int nbfs_add_regular_entry(struct inode *dir, const struct qstr *new_name,
				const struct qstr *orig_name,
				struct inode *inode, nid_t ino, umode_t mode)
{
	unsigned int bit_pos;
	unsigned int level;
	unsigned int current_depth;
	unsigned long bidx, block;
	nbfs_hash_t dentry_hash;
	unsigned int nbucket, nblock;
	struct page *dentry_page = NULL;
	struct nbfs_dentry_block *dentry_blk = NULL;
	struct nbfs_dentry_ptr d;
	struct page *page = NULL;
	int slots, err = 0;

	level = 0;
	slots = GET_DENTRY_SLOTS(new_name->len);
	dentry_hash = nbfs_dentry_hash(new_name, NULL);

	current_depth = NBFS_I(dir)->i_current_depth;
	if (NBFS_I(dir)->chash == dentry_hash) {
		level = NBFS_I(dir)->clevel;
		NBFS_I(dir)->chash = 0;
	}

start:
	if (time_to_inject(NBFS_I_SB(dir), FAULT_DIR_DEPTH)) {
		nbfs_show_injection_info(FAULT_DIR_DEPTH);
		return -ENOSPC;
	}

	if (unlikely(current_depth == MAX_DIR_HASH_DEPTH))
		return -ENOSPC;

	/* Increase the depth, if required */
	if (level == current_depth)
		++current_depth;

	nbucket = dir_buckets(level, NBFS_I(dir)->i_dir_level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, NBFS_I(dir)->i_dir_level,
				(le32_to_cpu(dentry_hash) % nbucket));

	for (block = bidx; block <= (bidx + nblock - 1); block++) {
		dentry_page = nbfs_get_new_data_page(dir, NULL, block, true);
		if (IS_ERR(dentry_page))
			return PTR_ERR(dentry_page);

		dentry_blk = page_address(dentry_page);
		bit_pos = nbfs_room_for_filename(&dentry_blk->dentry_bitmap,
						slots, NR_DENTRY_IN_BLOCK);
		if (bit_pos < NR_DENTRY_IN_BLOCK)
			goto add_dentry;

		nbfs_put_page(dentry_page, 1);
	}

	/* Move to next level to find the empty slot for new dentry */
	++level;
	goto start;
add_dentry:
	nbfs_wait_on_page_writeback(dentry_page, DATA, true, true);

	if (inode) {
		down_write(&NBFS_I(inode)->i_sem);
		page = nbfs_init_inode_metadata(inode, dir, new_name,
						orig_name, NULL);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto fail;
		}
	}

	make_dentry_ptr_block(NULL, &d, dentry_blk);
	nbfs_update_dentry(ino, mode, &d, new_name, dentry_hash, bit_pos);

	set_page_dirty(dentry_page);

	if (inode) {
		nbfs_i_pino_write(inode, dir->i_ino);
		nbfs_put_page(page, 1);
	}

	nbfs_update_parent_metadata(dir, inode, current_depth);
fail:
	if (inode)
		up_write(&NBFS_I(inode)->i_sem);

	nbfs_put_page(dentry_page, 1);

	return err;
}

int nbfs_add_dentry(struct inode *dir, struct fscrypt_name *fname,
				struct inode *inode, nid_t ino, umode_t mode)
{
	struct qstr new_name;
	int err = -EAGAIN;

	new_name.name = fname_name(fname);
	new_name.len = fname_len(fname);

	if (nbfs_has_inline_dentry(dir))
		err = nbfs_add_inline_entry(dir, &new_name, fname->usr_fname,
							inode, ino, mode);
	if (err == -EAGAIN)
		err = nbfs_add_regular_entry(dir, &new_name, fname->usr_fname,
							inode, ino, mode);

	nbfs_update_time(NBFS_I_SB(dir), REQ_TIME);
	return err;
}

/*
 * Caller should grab and release a rwsem by calling nbfs_lock_op() and
 * nbfs_unlock_op().
 */
int nbfs_do_add_link(struct inode *dir, const struct qstr *name,
				struct inode *inode, nid_t ino, umode_t mode)
{
	struct fscrypt_name fname;
	struct page *page = NULL;
	struct nbfs_dir_entry *de = NULL;
	int err;

	err = fscrypt_setup_filename(dir, name, 0, &fname);
	if (err)
		return err;

	/*
	 * An immature stakable filesystem shows a race condition between lookup
	 * and create. If we have same task when doing lookup and create, it's
	 * definitely fine as expected by VFS normally. Otherwise, let's just
	 * verify on-disk dentry one more time, which guarantees filesystem
	 * consistency more.
	 */
	if (current != NBFS_I(dir)->task) {
		de = __nbfs_find_entry(dir, &fname, &page);
		NBFS_I(dir)->task = NULL;
	}
	if (de) {
		nbfs_put_page(page, 0);
		err = -EEXIST;
	} else if (IS_ERR(page)) {
		err = PTR_ERR(page);
	} else {
		err = nbfs_add_dentry(dir, &fname, inode, ino, mode);
	}
	fscrypt_free_filename(&fname);
	return err;
}

int nbfs_do_tmpfile(struct inode *inode, struct inode *dir)
{
	struct page *page;
	int err = 0;

	down_write(&NBFS_I(inode)->i_sem);
	page = nbfs_init_inode_metadata(inode, dir, NULL, NULL, NULL);
	if (IS_ERR(page)) {
		err = PTR_ERR(page);
		goto fail;
	}
	nbfs_put_page(page, 1);

	clear_inode_flag(inode, FI_NEW_INODE);
	nbfs_update_time(NBFS_I_SB(inode), REQ_TIME);
fail:
	up_write(&NBFS_I(inode)->i_sem);
	return err;
}

void nbfs_drop_nlink(struct inode *dir, struct inode *inode)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);

	down_write(&NBFS_I(inode)->i_sem);

	if (S_ISDIR(inode->i_mode))
		nbfs_i_links_write(dir, false);
	inode->i_ctime = current_time(inode);

	nbfs_i_links_write(inode, false);
	if (S_ISDIR(inode->i_mode)) {
		nbfs_i_links_write(inode, false);
		nbfs_i_size_write(inode, 0);
	}
	up_write(&NBFS_I(inode)->i_sem);

	if (inode->i_nlink == 0)
		nbfs_add_orphan_inode(inode);
	else
		nbfs_release_orphan_inode(sbi);
}

/*
 * It only removes the dentry from the dentry page, corresponding name
 * entry in name page does not need to be touched during deletion.
 */
void nbfs_delete_entry(struct nbfs_dir_entry *dentry, struct page *page,
					struct inode *dir, struct inode *inode)
{
	struct	nbfs_dentry_block *dentry_blk;
	unsigned int bit_pos;
	int slots = GET_DENTRY_SLOTS(le16_to_cpu(dentry->name_len));
	int i;

	nbfs_update_time(NBFS_I_SB(dir), REQ_TIME);

	if (NBFS_OPTION(NBFS_I_SB(dir)).fsync_mode == FSYNC_MODE_STRICT)
		nbfs_add_ino_entry(NBFS_I_SB(dir), dir->i_ino, TRANS_DIR_INO);

	if (nbfs_has_inline_dentry(dir))
		return nbfs_delete_inline_entry(dentry, page, dir, inode);

	lock_page(page);
	nbfs_wait_on_page_writeback(page, DATA, true, true);

	dentry_blk = page_address(page);
	bit_pos = dentry - dentry_blk->dentry;
	for (i = 0; i < slots; i++)
		__clear_bit_le(bit_pos + i, &dentry_blk->dentry_bitmap);

	/* Let's check and deallocate this dentry page */
	bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
			NR_DENTRY_IN_BLOCK,
			0);
	set_page_dirty(page);

	dir->i_ctime = dir->i_mtime = current_time(dir);
	nbfs_mark_inode_dirty_sync(dir, false);

	if (inode)
		nbfs_drop_nlink(dir, inode);

	if (bit_pos == NR_DENTRY_IN_BLOCK &&
		!nbfs_truncate_hole(dir, page->index, page->index + 1)) {
		nbfs_clear_page_cache_dirty_tag(page);
		clear_page_dirty_for_io(page);
		nbfs_clear_page_private(page);
		ClearPageUptodate(page);
		clear_cold_data(page);
		inode_dec_dirty_pages(dir);
		nbfs_remove_dirty_inode(dir);
	}
	nbfs_put_page(page, 1);
}

bool nbfs_empty_dir(struct inode *dir)
{
	unsigned long bidx;
	struct page *dentry_page;
	unsigned int bit_pos;
	struct nbfs_dentry_block *dentry_blk;
	unsigned long nblock = dir_blocks(dir);

	if (nbfs_has_inline_dentry(dir))
		return nbfs_empty_inline_dir(dir);

	for (bidx = 0; bidx < nblock; bidx++) {
		dentry_page = nbfs_get_lock_data_page(dir, bidx, false);
		if (IS_ERR(dentry_page)) {
			if (PTR_ERR(dentry_page) == -ENOENT)
				continue;
			else
				return false;
		}

		dentry_blk = page_address(dentry_page);
		if (bidx == 0)
			bit_pos = 2;
		else
			bit_pos = 0;
		bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
						NR_DENTRY_IN_BLOCK,
						bit_pos);

		nbfs_put_page(dentry_page, 1);

		if (bit_pos < NR_DENTRY_IN_BLOCK)
			return false;
	}
	return true;
}

int nbfs_fill_dentries(struct dir_context *ctx, struct nbfs_dentry_ptr *d,
			unsigned int start_pos, struct fscrypt_str *fstr)
{
	unsigned char d_type = DT_UNKNOWN;
	unsigned int bit_pos;
	struct nbfs_dir_entry *de = NULL;
	struct fscrypt_str de_name = FSTR_INIT(NULL, 0);
	struct nbfs_sb_info *sbi = NBFS_I_SB(d->inode);
	struct blk_plug plug;
	bool readdir_ra = sbi->readdir_ra == 1;
	int err = 0;

	bit_pos = ((unsigned long)ctx->pos % d->max);

	if (readdir_ra)
		blk_start_plug(&plug);

	while (bit_pos < d->max) {
		bit_pos = find_next_bit_le(d->bitmap, d->max, bit_pos);
		if (bit_pos >= d->max)
			break;

		de = &d->dentry[bit_pos];
		if (de->name_len == 0) {
			bit_pos++;
			ctx->pos = start_pos + bit_pos;
			printk_ratelimited(
				"%s, invalid namelen(0), ino:%u, run fsck to fix.",
				KERN_WARNING, le32_to_cpu(de->ino));
			set_sbi_flag(sbi, SBI_NEED_FSCK);
			continue;
		}

		d_type = nbfs_get_de_type(de);

		de_name.name = d->filename[bit_pos];
		de_name.len = le16_to_cpu(de->name_len);

		/* check memory boundary before moving forward */
		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
		if (unlikely(bit_pos > d->max ||
				le16_to_cpu(de->name_len) > NBFS_NAME_LEN)) {
			nbfs_msg(sbi->sb, KERN_WARNING,
				"%s: corrupted namelen=%d, run fsck to fix.",
				__func__, le16_to_cpu(de->name_len));
			set_sbi_flag(sbi, SBI_NEED_FSCK);
			err = -EINVAL;
			goto out;
		}

		if (IS_ENCRYPTED(d->inode)) {
			int save_len = fstr->len;

			err = fscrypt_fname_disk_to_usr(d->inode,
						(u32)de->hash_code, 0,
						&de_name, fstr);
			if (err)
				goto out;

			de_name = *fstr;
			fstr->len = save_len;
		}

		if (!dir_emit(ctx, de_name.name, de_name.len,
					le32_to_cpu(de->ino), d_type)) {
			err = 1;
			goto out;
		}

		if (readdir_ra)
			nbfs_ra_node_page(sbi, le32_to_cpu(de->ino));

		ctx->pos = start_pos + bit_pos;
	}
out:
	if (readdir_ra)
		blk_finish_plug(&plug);
	return err;
}

static int nbfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	unsigned long npages = dir_blocks(inode);
	struct nbfs_dentry_block *dentry_blk = NULL;
	struct page *dentry_page = NULL;
	struct file_ra_state *ra = &file->f_ra;
	loff_t start_pos = ctx->pos;
	unsigned int n = ((unsigned long)ctx->pos / NR_DENTRY_IN_BLOCK);
	struct nbfs_dentry_ptr d;
	struct fscrypt_str fstr = FSTR_INIT(NULL, 0);
	int err = 0;

	if (IS_ENCRYPTED(inode)) {
		err = fscrypt_get_encryption_info(inode);
		if (err && err != -ENOKEY)
			goto out;

		err = fscrypt_fname_alloc_buffer(inode, NBFS_NAME_LEN, &fstr);
		if (err < 0)
			goto out;
	}

	if (nbfs_has_inline_dentry(inode)) {
		err = nbfs_read_inline_dir(file, ctx, &fstr);
		goto out_free;
	}

	for (; n < npages; n++, ctx->pos = n * NR_DENTRY_IN_BLOCK) {

		/* allow readdir() to be interrupted */
		if (fatal_signal_pending(current)) {
			err = -ERESTARTSYS;
			goto out_free;
		}
		cond_resched();

		/* readahead for multi pages of dir */
		if (npages - n > 1 && !ra_has_index(ra, n))
			page_cache_sync_readahead(inode->i_mapping, ra, file, n,
				min(npages - n, (pgoff_t)MAX_DIR_RA_PAGES));

		dentry_page = nbfs_find_data_page(inode, n);
		if (IS_ERR(dentry_page)) {
			err = PTR_ERR(dentry_page);
			if (err == -ENOENT) {
				err = 0;
				continue;
			} else {
				goto out_free;
			}
		}

		dentry_blk = page_address(dentry_page);

		make_dentry_ptr_block(inode, &d, dentry_blk);

		err = nbfs_fill_dentries(ctx, &d,
				n * NR_DENTRY_IN_BLOCK, &fstr);
		if (err) {
			nbfs_put_page(dentry_page, 0);
			break;
		}

		nbfs_put_page(dentry_page, 0);
	}
out_free:
	fscrypt_fname_free_buffer(&fstr);
out:
	trace_nbfs_readdir(inode, start_pos, ctx->pos, err);
	return err < 0 ? err : 0;
}

static int nbfs_dir_open(struct inode *inode, struct file *filp)
{
	if (IS_ENCRYPTED(inode))
		return fscrypt_get_encryption_info(inode) ? -EACCES : 0;
	return 0;
}

const struct file_operations nbfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= nbfs_readdir,
	.fsync		= nbfs_sync_file,
	.open		= nbfs_dir_open,
	.unlocked_ioctl	= nbfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = nbfs_compat_ioctl,
#endif
};
