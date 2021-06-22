// SPDX-License-Identifier: GPL-2.0
/*
 * fs/nbfs/namei.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/nbfs_fs.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/quotaops.h>

#include "nbfs.h"
#include "node.h"
#include "segment.h"
#include "xattr.h"
#include "acl.h"
#include <trace/events/nbfs.h>

static struct inode *nbfs_new_inode(struct inode *dir, umode_t mode)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	nid_t ino;
	struct inode *inode;
	bool nid_free = false;
	int xattr_size = 0;
	int err;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	nbfs_lock_op(sbi);
	if (!nbfs_alloc_nid(sbi, &ino)) {
		nbfs_unlock_op(sbi);
		err = -ENOSPC;
		goto fail;
	}
	nbfs_unlock_op(sbi);

	nid_free = true;

	inode_init_owner(inode, dir, mode);

	inode->i_ino = ino;
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	NBFS_I(inode)->i_crtime = inode->i_mtime;
	inode->i_generation = prandom_u32();

	if (S_ISDIR(inode->i_mode))
		NBFS_I(inode)->i_current_depth = 1;

	err = insert_inode_locked(inode);
	if (err) {
		err = -EINVAL;
		goto fail;
	}

	if (nbfs_sb_has_project_quota(sbi) &&
		(NBFS_I(dir)->i_flags & NBFS_PROJINHERIT_FL))
		NBFS_I(inode)->i_projid = NBFS_I(dir)->i_projid;
	else
		NBFS_I(inode)->i_projid = make_kprojid(&init_user_ns,
							NBFS_DEF_PROJID);

	err = dquot_initialize(inode);
	if (err)
		goto fail_drop;

	set_inode_flag(inode, FI_NEW_INODE);

	/* If the directory encrypted, then we should encrypt the inode. */
	if ((IS_ENCRYPTED(dir) || DUMMY_ENCRYPTION_ENABLED(sbi)) &&
				nbfs_may_encrypt(inode))
		nbfs_set_encrypted_inode(inode);

	if (nbfs_sb_has_extra_attr(sbi)) {
		set_inode_flag(inode, FI_EXTRA_ATTR);
		NBFS_I(inode)->i_extra_isize = NBFS_TOTAL_EXTRA_ATTR_SIZE;
	}

	if (test_opt(sbi, INLINE_XATTR))
		set_inode_flag(inode, FI_INLINE_XATTR);

	if (test_opt(sbi, INLINE_DATA) && nbfs_may_inline_data(inode))
		set_inode_flag(inode, FI_INLINE_DATA);
	if (nbfs_may_inline_dentry(inode))
		set_inode_flag(inode, FI_INLINE_DENTRY);

	if (nbfs_sb_has_flexible_inline_xattr(sbi)) {
		nbfs_bug_on(sbi, !nbfs_has_extra_attr(inode));
		if (nbfs_has_inline_xattr(inode))
			xattr_size = NBFS_OPTION(sbi).inline_xattr_size;
		/* Otherwise, will be 0 */
	} else if (nbfs_has_inline_xattr(inode) ||
				nbfs_has_inline_dentry(inode)) {
		xattr_size = DEFAULT_INLINE_XATTR_ADDRS;
	}
	NBFS_I(inode)->i_inline_xattr_size = xattr_size;

	nbfs_init_extent_tree(inode, NULL);

	stat_inc_inline_xattr(inode);
	stat_inc_inline_inode(inode);
	stat_inc_inline_dir(inode);

	NBFS_I(inode)->i_flags =
		nbfs_mask_flags(mode, NBFS_I(dir)->i_flags & NBFS_FL_INHERITED);

	if (S_ISDIR(inode->i_mode))
		NBFS_I(inode)->i_flags |= NBFS_INDEX_FL;

	if (NBFS_I(inode)->i_flags & NBFS_PROJINHERIT_FL)
		set_inode_flag(inode, FI_PROJ_INHERIT);

	nbfs_set_inode_flags(inode);

	trace_nbfs_new_inode(inode, 0);
	return inode;

fail:
	trace_nbfs_new_inode(inode, err);
	make_bad_inode(inode);
	if (nid_free)
		set_inode_flag(inode, FI_FREE_NID);
	iput(inode);
	return ERR_PTR(err);
fail_drop:
	trace_nbfs_new_inode(inode, err);
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	if (nid_free)
		set_inode_flag(inode, FI_FREE_NID);
	clear_nlink(inode);
	unlock_new_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}

static int is_extension_exist(const unsigned char *s, const char *sub)
{
	size_t slen = strlen(s);
	size_t sublen = strlen(sub);
	int i;

	/*
	 * filename format of multimedia file should be defined as:
	 * "filename + '.' + extension + (optional: '.' + temp extension)".
	 */
	if (slen < sublen + 2)
		return 0;

	for (i = 1; i < slen - sublen; i++) {
		if (s[i] != '.')
			continue;
		if (!strncasecmp(s + i + 1, sub, sublen))
			return 1;
	}

	return 0;
}

/*
 * Set multimedia files as cold files for hot/cold data separation
 */
static inline void set_file_temperature(struct nbfs_sb_info *sbi, struct inode *inode,
		const unsigned char *name)
{
	__u8 (*extlist)[NBFS_EXTENSION_LEN] = sbi->raw_super->extension_list;
	int i, cold_count, hot_count;

	down_read(&sbi->sb_lock);

	cold_count = le32_to_cpu(sbi->raw_super->extension_count);
	hot_count = sbi->raw_super->hot_ext_count;

	for (i = 0; i < cold_count + hot_count; i++) {
		if (is_extension_exist(name, extlist[i]))
			break;
	}

	up_read(&sbi->sb_lock);

	if (i == cold_count + hot_count)
		return;

	if (i < cold_count)
		file_set_cold(inode);
	else
		file_set_hot(inode);
}

int nbfs_update_extension_list(struct nbfs_sb_info *sbi, const char *name,
							bool hot, bool set)
{
	__u8 (*extlist)[NBFS_EXTENSION_LEN] = sbi->raw_super->extension_list;
	int cold_count = le32_to_cpu(sbi->raw_super->extension_count);
	int hot_count = sbi->raw_super->hot_ext_count;
	int total_count = cold_count + hot_count;
	int start, count;
	int i;

	if (set) {
		if (total_count == NBFS_MAX_EXTENSION)
			return -EINVAL;
	} else {
		if (!hot && !cold_count)
			return -EINVAL;
		if (hot && !hot_count)
			return -EINVAL;
	}

	if (hot) {
		start = cold_count;
		count = total_count;
	} else {
		start = 0;
		count = cold_count;
	}

	for (i = start; i < count; i++) {
		if (strcmp(name, extlist[i]))
			continue;

		if (set)
			return -EINVAL;

		memcpy(extlist[i], extlist[i + 1],
				NBFS_EXTENSION_LEN * (total_count - i - 1));
		memset(extlist[total_count - 1], 0, NBFS_EXTENSION_LEN);
		if (hot)
			sbi->raw_super->hot_ext_count = hot_count - 1;
		else
			sbi->raw_super->extension_count =
						cpu_to_le32(cold_count - 1);
		return 0;
	}

	if (!set)
		return -EINVAL;

	if (hot) {
		memcpy(extlist[count], name, strlen(name));
		sbi->raw_super->hot_ext_count = hot_count + 1;
	} else {
		char buf[NBFS_MAX_EXTENSION][NBFS_EXTENSION_LEN];

		memcpy(buf, &extlist[cold_count],
				NBFS_EXTENSION_LEN * hot_count);
		memset(extlist[cold_count], 0, NBFS_EXTENSION_LEN);
		memcpy(extlist[cold_count], name, strlen(name));
		memcpy(&extlist[cold_count + 1], buf,
				NBFS_EXTENSION_LEN * hot_count);
		sbi->raw_super->extension_count = cpu_to_le32(cold_count + 1);
	}
	return 0;
}

static int nbfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
						bool excl)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	struct inode *inode;
	nid_t ino = 0;
	int err;

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;
	err = nbfs_is_checkpoint_ready(sbi);
	if (err)
		return err;

	err = dquot_initialize(dir);
	if (err)
		return err;

	inode = nbfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (!test_opt(sbi, DISABLE_EXT_IDENTIFY))
		set_file_temperature(sbi, inode, dentry->d_name.name);

	inode->i_op = &nbfs_file_inode_operations;
	inode->i_fop = &nbfs_file_operations;
	inode->i_mapping->a_ops = &nbfs_dblock_aops;
	ino = inode->i_ino;

	nbfs_lock_op(sbi);
	err = nbfs_add_link(dentry, inode);
	if (err)
		goto out;
	nbfs_unlock_op(sbi);

	nbfs_alloc_nid_done(sbi, ino);

	d_instantiate_new(dentry, inode);

	if (IS_DIRSYNC(dir))
		nbfs_sync_fs(sbi->sb, 1);

	nbfs_balance_fs(sbi, true);
	return 0;
out:
	nbfs_handle_failed_inode(inode);
	return err;
}

static int nbfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	int err;

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;
	err = nbfs_is_checkpoint_ready(sbi);
	if (err)
		return err;

	err = fscrypt_prepare_link(old_dentry, dir, dentry);
	if (err)
		return err;

	if (is_inode_flag_set(dir, FI_PROJ_INHERIT) &&
			(!projid_eq(NBFS_I(dir)->i_projid,
			NBFS_I(old_dentry->d_inode)->i_projid)))
		return -EXDEV;

	err = dquot_initialize(dir);
	if (err)
		return err;

	nbfs_balance_fs(sbi, true);

	inode->i_ctime = current_time(inode);
	ihold(inode);

	set_inode_flag(inode, FI_INC_LINK);
	nbfs_lock_op(sbi);
	err = nbfs_add_link(dentry, inode);
	if (err)
		goto out;
	nbfs_unlock_op(sbi);

	d_instantiate(dentry, inode);

	if (IS_DIRSYNC(dir))
		nbfs_sync_fs(sbi->sb, 1);
	return 0;
out:
	clear_inode_flag(inode, FI_INC_LINK);
	iput(inode);
	nbfs_unlock_op(sbi);
	return err;
}

struct dentry *nbfs_get_parent(struct dentry *child)
{
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct page *page;
	unsigned long ino = nbfs_inode_by_name(d_inode(child), &dotdot, &page);
	if (!ino) {
		if (IS_ERR(page))
			return ERR_CAST(page);
		return ERR_PTR(-ENOENT);
	}
	return d_obtain_alias(nbfs_iget(child->d_sb, ino));
}

static int __recover_dot_dentries(struct inode *dir, nid_t pino)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	struct qstr dot = QSTR_INIT(".", 1);
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct nbfs_dir_entry *de;
	struct page *page;
	int err = 0;

	if (nbfs_readonly(sbi->sb)) {
		nbfs_msg(sbi->sb, KERN_INFO,
			"skip recovering inline_dots inode (ino:%lu, pino:%u) "
			"in readonly mountpoint", dir->i_ino, pino);
		return 0;
	}

	err = dquot_initialize(dir);
	if (err)
		return err;

	nbfs_balance_fs(sbi, true);

	nbfs_lock_op(sbi);

	de = nbfs_find_entry(dir, &dot, &page);
	if (de) {
		nbfs_put_page(page, 0);
	} else if (IS_ERR(page)) {
		err = PTR_ERR(page);
		goto out;
	} else {
		err = nbfs_do_add_link(dir, &dot, NULL, dir->i_ino, S_IFDIR);
		if (err)
			goto out;
	}

	de = nbfs_find_entry(dir, &dotdot, &page);
	if (de)
		nbfs_put_page(page, 0);
	else if (IS_ERR(page))
		err = PTR_ERR(page);
	else
		err = nbfs_do_add_link(dir, &dotdot, NULL, pino, S_IFDIR);
out:
	if (!err)
		clear_inode_flag(dir, FI_INLINE_DOTS);

	nbfs_unlock_op(sbi);
	return err;
}

static struct dentry *nbfs_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct inode *inode = NULL;
	struct nbfs_dir_entry *de;
	struct page *page;
	struct dentry *new;
	nid_t ino = -1;
	int err = 0;
	unsigned int root_ino = NBFS_ROOT_INO(NBFS_I_SB(dir));

	trace_nbfs_lookup_start(dir, dentry, flags);

	err = fscrypt_prepare_lookup(dir, dentry, flags);
	if (err)
		goto out;

	if (dentry->d_name.len > NBFS_NAME_LEN) {
		err = -ENAMETOOLONG;
		goto out;
	}

	de = nbfs_find_entry(dir, &dentry->d_name, &page);
	if (!de) {
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto out;
		}
		goto out_splice;
	}

	ino = le32_to_cpu(de->ino);
	nbfs_put_page(page, 0);

	inode = nbfs_iget(dir->i_sb, ino);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	if ((dir->i_ino == root_ino) && nbfs_has_inline_dots(dir)) {
		err = __recover_dot_dentries(dir, root_ino);
		if (err)
			goto out_iput;
	}

	if (nbfs_has_inline_dots(inode)) {
		err = __recover_dot_dentries(inode, dir->i_ino);
		if (err)
			goto out_iput;
	}
	if (IS_ENCRYPTED(dir) &&
	    (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)) &&
	    !fscrypt_has_permitted_context(dir, inode)) {
		nbfs_msg(inode->i_sb, KERN_WARNING,
			 "Inconsistent encryption contexts: %lu/%lu",
			 dir->i_ino, inode->i_ino);
		err = -EPERM;
		goto out_iput;
	}
out_splice:
	new = d_splice_alias(inode, dentry);
	if (IS_ERR(new))
		err = PTR_ERR(new);
	trace_nbfs_lookup_end(dir, dentry, ino, err);
	return new;
out_iput:
	iput(inode);
out:
	trace_nbfs_lookup_end(dir, dentry, ino, err);
	return ERR_PTR(err);
}

static int nbfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	struct inode *inode = d_inode(dentry);
	struct nbfs_dir_entry *de;
	struct page *page;
	int err = -ENOENT;

	trace_nbfs_unlink_enter(dir, dentry);

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;

	err = dquot_initialize(dir);
	if (err)
		return err;
	err = dquot_initialize(inode);
	if (err)
		return err;

	de = nbfs_find_entry(dir, &dentry->d_name, &page);
	if (!de) {
		if (IS_ERR(page))
			err = PTR_ERR(page);
		goto fail;
	}

	nbfs_balance_fs(sbi, true);

	nbfs_lock_op(sbi);
	err = nbfs_acquire_orphan_inode(sbi);
	if (err) {
		nbfs_unlock_op(sbi);
		nbfs_put_page(page, 0);
		goto fail;
	}
	nbfs_delete_entry(de, page, dir, inode);
	nbfs_unlock_op(sbi);

	if (IS_DIRSYNC(dir))
		nbfs_sync_fs(sbi->sb, 1);
fail:
	trace_nbfs_unlink_exit(inode, err);
	return err;
}

static const char *nbfs_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	const char *link = page_get_link(dentry, inode, done);
	if (!IS_ERR(link) && !*link) {
		/* this is broken symlink case */
		do_delayed_call(done);
		clear_delayed_call(done);
		link = ERR_PTR(-ENOENT);
	}
	return link;
}

static int nbfs_symlink(struct inode *dir, struct dentry *dentry,
					const char *symname)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	struct inode *inode;
	size_t len = strlen(symname);
	struct fscrypt_str disk_link;
	int err;

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;
	err = nbfs_is_checkpoint_ready(sbi);
	if (err)
		return err;

	err = fscrypt_prepare_symlink(dir, symname, len, dir->i_sb->s_blocksize,
				      &disk_link);
	if (err)
		return err;

	err = dquot_initialize(dir);
	if (err)
		return err;

	inode = nbfs_new_inode(dir, S_IFLNK | S_IRWXUGO);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (IS_ENCRYPTED(inode))
		inode->i_op = &nbfs_encrypted_symlink_inode_operations;
	else
		inode->i_op = &nbfs_symlink_inode_operations;
	inode_nohighmem(inode);
	inode->i_mapping->a_ops = &nbfs_dblock_aops;

	nbfs_lock_op(sbi);
	err = nbfs_add_link(dentry, inode);
	if (err)
		goto out_nbfs_handle_failed_inode;
	nbfs_unlock_op(sbi);
	nbfs_alloc_nid_done(sbi, inode->i_ino);

	err = fscrypt_encrypt_symlink(inode, symname, len, &disk_link);
	if (err)
		goto err_out;

	err = page_symlink(inode, disk_link.name, disk_link.len);

err_out:
	d_instantiate_new(dentry, inode);

	/*
	 * Let's flush symlink data in order to avoid broken symlink as much as
	 * possible. Nevertheless, fsyncing is the best way, but there is no
	 * way to get a file descriptor in order to flush that.
	 *
	 * Note that, it needs to do dir->fsync to make this recoverable.
	 * If the symlink path is stored into inline_data, there is no
	 * performance regression.
	 */
	if (!err) {
		filemap_write_and_wait_range(inode->i_mapping, 0,
							disk_link.len - 1);

		if (IS_DIRSYNC(dir))
			nbfs_sync_fs(sbi->sb, 1);
	} else {
		nbfs_unlink(dir, dentry);
	}

	nbfs_balance_fs(sbi, true);
	goto out_free_encrypted_link;

out_nbfs_handle_failed_inode:
	nbfs_handle_failed_inode(inode);
out_free_encrypted_link:
	if (disk_link.name != (unsigned char *)symname)
		kvfree(disk_link.name);
	return err;
}

static int nbfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	struct inode *inode;
	int err;

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;

	err = dquot_initialize(dir);
	if (err)
		return err;

	inode = nbfs_new_inode(dir, S_IFDIR | mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &nbfs_dir_inode_operations;
	inode->i_fop = &nbfs_dir_operations;
	inode->i_mapping->a_ops = &nbfs_dblock_aops;
	inode_nohighmem(inode);

	set_inode_flag(inode, FI_INC_LINK);
	nbfs_lock_op(sbi);
	err = nbfs_add_link(dentry, inode);
	if (err)
		goto out_fail;
	nbfs_unlock_op(sbi);

	nbfs_alloc_nid_done(sbi, inode->i_ino);

	d_instantiate_new(dentry, inode);

	if (IS_DIRSYNC(dir))
		nbfs_sync_fs(sbi->sb, 1);

	nbfs_balance_fs(sbi, true);
	return 0;

out_fail:
	clear_inode_flag(inode, FI_INC_LINK);
	nbfs_handle_failed_inode(inode);
	return err;
}

static int nbfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	if (nbfs_empty_dir(inode))
		return nbfs_unlink(dir, dentry);
	return -ENOTEMPTY;
}

static int nbfs_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t rdev)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	struct inode *inode;
	int err = 0;

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;
	err = nbfs_is_checkpoint_ready(sbi);
	if (err)
		return err;

	err = dquot_initialize(dir);
	if (err)
		return err;

	inode = nbfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	init_special_inode(inode, inode->i_mode, rdev);
	inode->i_op = &nbfs_special_inode_operations;

	nbfs_lock_op(sbi);
	err = nbfs_add_link(dentry, inode);
	if (err)
		goto out;
	nbfs_unlock_op(sbi);

	nbfs_alloc_nid_done(sbi, inode->i_ino);

	d_instantiate_new(dentry, inode);

	if (IS_DIRSYNC(dir))
		nbfs_sync_fs(sbi->sb, 1);

	nbfs_balance_fs(sbi, true);
	return 0;
out:
	nbfs_handle_failed_inode(inode);
	return err;
}

static int __nbfs_tmpfile(struct inode *dir, struct dentry *dentry,
					umode_t mode, struct inode **whiteout)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);
	struct inode *inode;
	int err;

	err = dquot_initialize(dir);
	if (err)
		return err;

	inode = nbfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (whiteout) {
		init_special_inode(inode, inode->i_mode, WHITEOUT_DEV);
		inode->i_op = &nbfs_special_inode_operations;
	} else {
		inode->i_op = &nbfs_file_inode_operations;
		inode->i_fop = &nbfs_file_operations;
		inode->i_mapping->a_ops = &nbfs_dblock_aops;
	}

	nbfs_lock_op(sbi);
	err = nbfs_acquire_orphan_inode(sbi);
	if (err)
		goto out;

	err = nbfs_do_tmpfile(inode, dir);
	if (err)
		goto release_out;

	/*
	 * add this non-linked tmpfile to orphan list, in this way we could
	 * remove all unused data of tmpfile after abnormal power-off.
	 */
	nbfs_add_orphan_inode(inode);
	nbfs_alloc_nid_done(sbi, inode->i_ino);

	if (whiteout) {
		nbfs_i_links_write(inode, false);
		*whiteout = inode;
	} else {
		d_tmpfile(dentry, inode);
	}
	/* link_count was changed by d_tmpfile as well. */
	nbfs_unlock_op(sbi);
	unlock_new_inode(inode);

	nbfs_balance_fs(sbi, true);
	return 0;

release_out:
	nbfs_release_orphan_inode(sbi);
out:
	nbfs_handle_failed_inode(inode);
	return err;
}

static int nbfs_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(dir);

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;

	if (IS_ENCRYPTED(dir) || DUMMY_ENCRYPTION_ENABLED(sbi)) {
		int err = fscrypt_get_encryption_info(dir);
		if (err)
			return err;
	}

	return __nbfs_tmpfile(dir, dentry, mode, NULL);
}

static int nbfs_create_whiteout(struct inode *dir, struct inode **whiteout)
{
	if (unlikely(nbfs_cp_error(NBFS_I_SB(dir))))
		return -EIO;

	return __nbfs_tmpfile(dir, NULL, S_IFCHR | WHITEOUT_MODE, whiteout);
}

static int nbfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(old_dir);
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	struct inode *whiteout = NULL;
	struct page *old_dir_page;
	struct page *old_page, *new_page = NULL;
	struct nbfs_dir_entry *old_dir_entry = NULL;
	struct nbfs_dir_entry *old_entry;
	struct nbfs_dir_entry *new_entry;
	bool is_old_inline = nbfs_has_inline_dentry(old_dir);
	int err;

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;
	err = nbfs_is_checkpoint_ready(sbi);
	if (err)
		return err;

	if (is_inode_flag_set(new_dir, FI_PROJ_INHERIT) &&
			(!projid_eq(NBFS_I(new_dir)->i_projid,
			NBFS_I(old_dentry->d_inode)->i_projid)))
		return -EXDEV;

	err = dquot_initialize(old_dir);
	if (err)
		goto out;

	err = dquot_initialize(new_dir);
	if (err)
		goto out;

	if (new_inode) {
		err = dquot_initialize(new_inode);
		if (err)
			goto out;
	}

	err = -ENOENT;
	old_entry = nbfs_find_entry(old_dir, &old_dentry->d_name, &old_page);
	if (!old_entry) {
		if (IS_ERR(old_page))
			err = PTR_ERR(old_page);
		goto out;
	}

	if (S_ISDIR(old_inode->i_mode)) {
		old_dir_entry = nbfs_parent_dir(old_inode, &old_dir_page);
		if (!old_dir_entry) {
			if (IS_ERR(old_dir_page))
				err = PTR_ERR(old_dir_page);
			goto out_old;
		}
	}

	if (flags & RENAME_WHITEOUT) {
		err = nbfs_create_whiteout(old_dir, &whiteout);
		if (err)
			goto out_dir;
	}

	if (new_inode) {

		err = -ENOTEMPTY;
		if (old_dir_entry && !nbfs_empty_dir(new_inode))
			goto out_whiteout;

		err = -ENOENT;
		new_entry = nbfs_find_entry(new_dir, &new_dentry->d_name,
						&new_page);
		if (!new_entry) {
			if (IS_ERR(new_page))
				err = PTR_ERR(new_page);
			goto out_whiteout;
		}

		nbfs_balance_fs(sbi, true);

		nbfs_lock_op(sbi);

		err = nbfs_acquire_orphan_inode(sbi);
		if (err)
			goto put_out_dir;

		nbfs_set_link(new_dir, new_entry, new_page, old_inode);

		new_inode->i_ctime = current_time(new_inode);
		down_write(&NBFS_I(new_inode)->i_sem);
		if (old_dir_entry)
			nbfs_i_links_write(new_inode, false);
		nbfs_i_links_write(new_inode, false);
		up_write(&NBFS_I(new_inode)->i_sem);

		if (!new_inode->i_nlink)
			nbfs_add_orphan_inode(new_inode);
		else
			nbfs_release_orphan_inode(sbi);
	} else {
		nbfs_balance_fs(sbi, true);

		nbfs_lock_op(sbi);

		err = nbfs_add_link(new_dentry, old_inode);
		if (err) {
			nbfs_unlock_op(sbi);
			goto out_whiteout;
		}

		if (old_dir_entry)
			nbfs_i_links_write(new_dir, true);

		/*
		 * old entry and new entry can locate in the same inline
		 * dentry in inode, when attaching new entry in inline dentry,
		 * it could force inline dentry conversion, after that,
		 * old_entry and old_page will point to wrong address, in
		 * order to avoid this, let's do the check and update here.
		 */
		if (is_old_inline && !nbfs_has_inline_dentry(old_dir)) {
			nbfs_put_page(old_page, 0);
			old_page = NULL;

			old_entry = nbfs_find_entry(old_dir,
						&old_dentry->d_name, &old_page);
			if (!old_entry) {
				err = -ENOENT;
				if (IS_ERR(old_page))
					err = PTR_ERR(old_page);
				nbfs_unlock_op(sbi);
				goto out_whiteout;
			}
		}
	}

	down_write(&NBFS_I(old_inode)->i_sem);
	if (!old_dir_entry || whiteout)
		file_lost_pino(old_inode);
	else
		NBFS_I(old_inode)->i_pino = new_dir->i_ino;
	up_write(&NBFS_I(old_inode)->i_sem);

	old_inode->i_ctime = current_time(old_inode);
	nbfs_mark_inode_dirty_sync(old_inode, false);

	nbfs_delete_entry(old_entry, old_page, old_dir, NULL);

	if (whiteout) {
		whiteout->i_state |= I_LINKABLE;
		set_inode_flag(whiteout, FI_INC_LINK);
		err = nbfs_add_link(old_dentry, whiteout);
		if (err)
			goto put_out_dir;
		whiteout->i_state &= ~I_LINKABLE;
		iput(whiteout);
	}

	if (old_dir_entry) {
		if (old_dir != new_dir && !whiteout)
			nbfs_set_link(old_inode, old_dir_entry,
						old_dir_page, new_dir);
		else
			nbfs_put_page(old_dir_page, 0);
		nbfs_i_links_write(old_dir, false);
	}
	if (NBFS_OPTION(sbi).fsync_mode == FSYNC_MODE_STRICT) {
		nbfs_add_ino_entry(sbi, new_dir->i_ino, TRANS_DIR_INO);
		if (S_ISDIR(old_inode->i_mode))
			nbfs_add_ino_entry(sbi, old_inode->i_ino,
							TRANS_DIR_INO);
	}

	nbfs_unlock_op(sbi);

	if (IS_DIRSYNC(old_dir) || IS_DIRSYNC(new_dir))
		nbfs_sync_fs(sbi->sb, 1);

	nbfs_update_time(sbi, REQ_TIME);
	return 0;

put_out_dir:
	nbfs_unlock_op(sbi);
	if (new_page)
		nbfs_put_page(new_page, 0);
out_whiteout:
	if (whiteout)
		iput(whiteout);
out_dir:
	if (old_dir_entry)
		nbfs_put_page(old_dir_page, 0);
out_old:
	nbfs_put_page(old_page, 0);
out:
	return err;
}

static int nbfs_cross_rename(struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(old_dir);
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);
	struct page *old_dir_page, *new_dir_page;
	struct page *old_page, *new_page;
	struct nbfs_dir_entry *old_dir_entry = NULL, *new_dir_entry = NULL;
	struct nbfs_dir_entry *old_entry, *new_entry;
	int old_nlink = 0, new_nlink = 0;
	int err;

	if (unlikely(nbfs_cp_error(sbi)))
		return -EIO;
	err = nbfs_is_checkpoint_ready(sbi);
	if (err)
		return err;

	if ((is_inode_flag_set(new_dir, FI_PROJ_INHERIT) &&
			!projid_eq(NBFS_I(new_dir)->i_projid,
			NBFS_I(old_dentry->d_inode)->i_projid)) ||
	    (is_inode_flag_set(new_dir, FI_PROJ_INHERIT) &&
			!projid_eq(NBFS_I(old_dir)->i_projid,
			NBFS_I(new_dentry->d_inode)->i_projid)))
		return -EXDEV;

	err = dquot_initialize(old_dir);
	if (err)
		goto out;

	err = dquot_initialize(new_dir);
	if (err)
		goto out;

	err = -ENOENT;
	old_entry = nbfs_find_entry(old_dir, &old_dentry->d_name, &old_page);
	if (!old_entry) {
		if (IS_ERR(old_page))
			err = PTR_ERR(old_page);
		goto out;
	}

	new_entry = nbfs_find_entry(new_dir, &new_dentry->d_name, &new_page);
	if (!new_entry) {
		if (IS_ERR(new_page))
			err = PTR_ERR(new_page);
		goto out_old;
	}

	/* prepare for updating ".." directory entry info later */
	if (old_dir != new_dir) {
		if (S_ISDIR(old_inode->i_mode)) {
			old_dir_entry = nbfs_parent_dir(old_inode,
							&old_dir_page);
			if (!old_dir_entry) {
				if (IS_ERR(old_dir_page))
					err = PTR_ERR(old_dir_page);
				goto out_new;
			}
		}

		if (S_ISDIR(new_inode->i_mode)) {
			new_dir_entry = nbfs_parent_dir(new_inode,
							&new_dir_page);
			if (!new_dir_entry) {
				if (IS_ERR(new_dir_page))
					err = PTR_ERR(new_dir_page);
				goto out_old_dir;
			}
		}
	}

	/*
	 * If cross rename between file and directory those are not
	 * in the same directory, we will inc nlink of file's parent
	 * later, so we should check upper boundary of its nlink.
	 */
	if ((!old_dir_entry || !new_dir_entry) &&
				old_dir_entry != new_dir_entry) {
		old_nlink = old_dir_entry ? -1 : 1;
		new_nlink = -old_nlink;
		err = -EMLINK;
		if ((old_nlink > 0 && old_dir->i_nlink >= NBFS_LINK_MAX) ||
			(new_nlink > 0 && new_dir->i_nlink >= NBFS_LINK_MAX))
			goto out_new_dir;
	}

	nbfs_balance_fs(sbi, true);

	nbfs_lock_op(sbi);

	/* update ".." directory entry info of old dentry */
	if (old_dir_entry)
		nbfs_set_link(old_inode, old_dir_entry, old_dir_page, new_dir);

	/* update ".." directory entry info of new dentry */
	if (new_dir_entry)
		nbfs_set_link(new_inode, new_dir_entry, new_dir_page, old_dir);

	/* update directory entry info of old dir inode */
	nbfs_set_link(old_dir, old_entry, old_page, new_inode);

	down_write(&NBFS_I(old_inode)->i_sem);
	file_lost_pino(old_inode);
	up_write(&NBFS_I(old_inode)->i_sem);

	old_dir->i_ctime = current_time(old_dir);
	if (old_nlink) {
		down_write(&NBFS_I(old_dir)->i_sem);
		nbfs_i_links_write(old_dir, old_nlink > 0);
		up_write(&NBFS_I(old_dir)->i_sem);
	}
	nbfs_mark_inode_dirty_sync(old_dir, false);

	/* update directory entry info of new dir inode */
	nbfs_set_link(new_dir, new_entry, new_page, old_inode);

	down_write(&NBFS_I(new_inode)->i_sem);
	file_lost_pino(new_inode);
	up_write(&NBFS_I(new_inode)->i_sem);

	new_dir->i_ctime = current_time(new_dir);
	if (new_nlink) {
		down_write(&NBFS_I(new_dir)->i_sem);
		nbfs_i_links_write(new_dir, new_nlink > 0);
		up_write(&NBFS_I(new_dir)->i_sem);
	}
	nbfs_mark_inode_dirty_sync(new_dir, false);

	if (NBFS_OPTION(sbi).fsync_mode == FSYNC_MODE_STRICT) {
		nbfs_add_ino_entry(sbi, old_dir->i_ino, TRANS_DIR_INO);
		nbfs_add_ino_entry(sbi, new_dir->i_ino, TRANS_DIR_INO);
	}

	nbfs_unlock_op(sbi);

	if (IS_DIRSYNC(old_dir) || IS_DIRSYNC(new_dir))
		nbfs_sync_fs(sbi->sb, 1);

	nbfs_update_time(sbi, REQ_TIME);
	return 0;
out_new_dir:
	if (new_dir_entry) {
		nbfs_put_page(new_dir_page, 0);
	}
out_old_dir:
	if (old_dir_entry) {
		nbfs_put_page(old_dir_page, 0);
	}
out_new:
	nbfs_put_page(new_page, 0);
out_old:
	nbfs_put_page(old_page, 0);
out:
	return err;
}

static int nbfs_rename2(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	int err;

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;

	err = fscrypt_prepare_rename(old_dir, old_dentry, new_dir, new_dentry,
				     flags);
	if (err)
		return err;

	if (flags & RENAME_EXCHANGE) {
		return nbfs_cross_rename(old_dir, old_dentry,
					 new_dir, new_dentry);
	}
	/*
	 * VFS has already handled the new dentry existence case,
	 * here, we just deal with "RENAME_NOREPLACE" as regular rename.
	 */
	return nbfs_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

static const char *nbfs_encrypted_get_link(struct dentry *dentry,
					   struct inode *inode,
					   struct delayed_call *done)
{
	struct page *page;
	const char *target;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	page = read_mapping_page(inode->i_mapping, 0, NULL);
	if (IS_ERR(page))
		return ERR_CAST(page);

	target = fscrypt_get_symlink(inode, page_address(page),
				     inode->i_sb->s_blocksize, done);
	put_page(page);
	return target;
}

const struct inode_operations nbfs_encrypted_symlink_inode_operations = {
	.get_link       = nbfs_encrypted_get_link,
	.getattr	= nbfs_getattr,
	.setattr	= nbfs_setattr,
#ifdef CONFIG_NBFS_FS_XATTR
	.listxattr	= nbfs_listxattr,
#endif
};

const struct inode_operations nbfs_dir_inode_operations = {
	.create		= nbfs_create,
	.lookup		= nbfs_lookup,
	.link		= nbfs_link,
	.unlink		= nbfs_unlink,
	.symlink	= nbfs_symlink,
	.mkdir		= nbfs_mkdir,
	.rmdir		= nbfs_rmdir,
	.mknod		= nbfs_mknod,
	.rename		= nbfs_rename2,
	.tmpfile	= nbfs_tmpfile,
	.getattr	= nbfs_getattr,
	.setattr	= nbfs_setattr,
	.get_acl	= nbfs_get_acl,
	.set_acl	= nbfs_set_acl,
#ifdef CONFIG_NBFS_FS_XATTR
	.listxattr	= nbfs_listxattr,
#endif
};

const struct inode_operations nbfs_symlink_inode_operations = {
	.get_link       = nbfs_get_link,
	.getattr	= nbfs_getattr,
	.setattr	= nbfs_setattr,
#ifdef CONFIG_NBFS_FS_XATTR
	.listxattr	= nbfs_listxattr,
#endif
};

const struct inode_operations nbfs_special_inode_operations = {
	.getattr	= nbfs_getattr,
	.setattr        = nbfs_setattr,
	.get_acl	= nbfs_get_acl,
	.set_acl	= nbfs_set_acl,
#ifdef CONFIG_NBFS_FS_XATTR
	.listxattr	= nbfs_listxattr,
#endif
};
