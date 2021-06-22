// SPDX-License-Identifier: GPL-2.0
/*
 * fs/nbfs/xattr.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Portions of this code from linux/fs/ext2/xattr.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher <agruen@suse.de>
 *
 * Fix by Harrison Xing <harrison@mountainviewdata.com>.
 * Extended attributes for symlinks and special files added per
 *  suggestion of Luka Renko <luka.renko@hermes.si>.
 * xattr consolidation Copyright (c) 2004 James Morris <jmorris@redhat.com>,
 *  Red Hat Inc.
 */
#include <linux/rwsem.h>
#include <linux/nbfs_fs.h>
#include <linux/security.h>
#include <linux/posix_acl_xattr.h>
#include "nbfs.h"
#include "xattr.h"

static int nbfs_xattr_generic_get(const struct xattr_handler *handler,
		struct dentry *unused, struct inode *inode,
		const char *name, void *buffer, size_t size)
{
	struct nbfs_sb_info *sbi = NBFS_SB(inode->i_sb);

	switch (handler->flags) {
	case NBFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case NBFS_XATTR_INDEX_TRUSTED:
	case NBFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}
	return nbfs_getxattr(inode, handler->flags, name,
			     buffer, size, NULL);
}

static int nbfs_xattr_generic_set(const struct xattr_handler *handler,
		struct dentry *unused, struct inode *inode,
		const char *name, const void *value,
		size_t size, int flags)
{
	struct nbfs_sb_info *sbi = NBFS_SB(inode->i_sb);

	switch (handler->flags) {
	case NBFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case NBFS_XATTR_INDEX_TRUSTED:
	case NBFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}
	return nbfs_setxattr(inode, handler->flags, name,
					value, size, NULL, flags);
}

static bool nbfs_xattr_user_list(struct dentry *dentry)
{
	struct nbfs_sb_info *sbi = NBFS_SB(dentry->d_sb);

	return test_opt(sbi, XATTR_USER);
}

static bool nbfs_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static int nbfs_xattr_advise_get(const struct xattr_handler *handler,
		struct dentry *unused, struct inode *inode,
		const char *name, void *buffer, size_t size)
{
	if (buffer)
		*((char *)buffer) = NBFS_I(inode)->i_advise;
	return sizeof(char);
}

static int nbfs_xattr_advise_set(const struct xattr_handler *handler,
		struct dentry *unused, struct inode *inode,
		const char *name, const void *value,
		size_t size, int flags)
{
	unsigned char old_advise = NBFS_I(inode)->i_advise;
	unsigned char new_advise;

	if (!inode_owner_or_capable(inode))
		return -EPERM;
	if (value == NULL)
		return -EINVAL;

	new_advise = *(char *)value;
	if (new_advise & ~FADVISE_MODIFIABLE_BITS)
		return -EINVAL;

	new_advise = new_advise & FADVISE_MODIFIABLE_BITS;
	new_advise |= old_advise & ~FADVISE_MODIFIABLE_BITS;

	NBFS_I(inode)->i_advise = new_advise;
	nbfs_mark_inode_dirty_sync(inode, true);
	return 0;
}

#ifdef CONFIG_NBFS_FS_SECURITY
static int nbfs_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *page)
{
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = nbfs_setxattr(inode, NBFS_XATTR_INDEX_SECURITY,
				xattr->name, xattr->value,
				xattr->value_len, (struct page *)page, 0);
		if (err < 0)
			break;
	}
	return err;
}

int nbfs_init_security(struct inode *inode, struct inode *dir,
				const struct qstr *qstr, struct page *ipage)
{
	return security_inode_init_security(inode, dir, qstr,
				&nbfs_initxattrs, ipage);
}
#endif

const struct xattr_handler nbfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.flags	= NBFS_XATTR_INDEX_USER,
	.list	= nbfs_xattr_user_list,
	.get	= nbfs_xattr_generic_get,
	.set	= nbfs_xattr_generic_set,
};

const struct xattr_handler nbfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.flags	= NBFS_XATTR_INDEX_TRUSTED,
	.list	= nbfs_xattr_trusted_list,
	.get	= nbfs_xattr_generic_get,
	.set	= nbfs_xattr_generic_set,
};

const struct xattr_handler nbfs_xattr_advise_handler = {
	.name	= NBFS_SYSTEM_ADVISE_NAME,
	.flags	= NBFS_XATTR_INDEX_ADVISE,
	.get    = nbfs_xattr_advise_get,
	.set    = nbfs_xattr_advise_set,
};

const struct xattr_handler nbfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.flags	= NBFS_XATTR_INDEX_SECURITY,
	.get	= nbfs_xattr_generic_get,
	.set	= nbfs_xattr_generic_set,
};

static const struct xattr_handler *nbfs_xattr_handler_map[] = {
	[NBFS_XATTR_INDEX_USER] = &nbfs_xattr_user_handler,
#ifdef CONFIG_NBFS_FS_POSIX_ACL
	[NBFS_XATTR_INDEX_POSIX_ACL_ACCESS] = &posix_acl_access_xattr_handler,
	[NBFS_XATTR_INDEX_POSIX_ACL_DEFAULT] = &posix_acl_default_xattr_handler,
#endif
	[NBFS_XATTR_INDEX_TRUSTED] = &nbfs_xattr_trusted_handler,
#ifdef CONFIG_NBFS_FS_SECURITY
	[NBFS_XATTR_INDEX_SECURITY] = &nbfs_xattr_security_handler,
#endif
	[NBFS_XATTR_INDEX_ADVISE] = &nbfs_xattr_advise_handler,
};

const struct xattr_handler *nbfs_xattr_handlers[] = {
	&nbfs_xattr_user_handler,
#ifdef CONFIG_NBFS_FS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
	&nbfs_xattr_trusted_handler,
#ifdef CONFIG_NBFS_FS_SECURITY
	&nbfs_xattr_security_handler,
#endif
	&nbfs_xattr_advise_handler,
	NULL,
};

static inline const struct xattr_handler *nbfs_xattr_handler(int index)
{
	const struct xattr_handler *handler = NULL;

	if (index > 0 && index < ARRAY_SIZE(nbfs_xattr_handler_map))
		handler = nbfs_xattr_handler_map[index];
	return handler;
}

static struct nbfs_xattr_entry *__find_xattr(void *base_addr, int index,
					size_t len, const char *name)
{
	struct nbfs_xattr_entry *entry;

	list_for_each_xattr(entry, base_addr) {
		if (entry->e_name_index != index)
			continue;
		if (entry->e_name_len != len)
			continue;
		if (!memcmp(entry->e_name, name, len))
			break;
	}
	return entry;
}

static struct nbfs_xattr_entry *__find_inline_xattr(struct inode *inode,
				void *base_addr, void **last_addr, int index,
				size_t len, const char *name)
{
	struct nbfs_xattr_entry *entry;
	unsigned int inline_size = inline_xattr_size(inode);
	void *max_addr = base_addr + inline_size;

	list_for_each_xattr(entry, base_addr) {
		if ((void *)entry + sizeof(__u32) > max_addr ||
			(void *)XATTR_NEXT_ENTRY(entry) > max_addr) {
			*last_addr = entry;
			return NULL;
		}
		if (entry->e_name_index != index)
			continue;
		if (entry->e_name_len != len)
			continue;
		if (!memcmp(entry->e_name, name, len))
			break;
	}

	/* inline xattr header or entry across max inline xattr size */
	if (IS_XATTR_LAST_ENTRY(entry) &&
		(void *)entry + sizeof(__u32) > max_addr) {
		*last_addr = entry;
		return NULL;
	}
	return entry;
}

static int read_inline_xattr(struct inode *inode, struct page *ipage,
							void *txattr_addr)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	unsigned int inline_size = inline_xattr_size(inode);
	struct page *page = NULL;
	void *inline_addr;

	if (ipage) {
		inline_addr = inline_xattr_addr(inode, ipage);
	} else {
		page = nbfs_get_node_page(sbi, inode->i_ino);
		if (IS_ERR(page))
			return PTR_ERR(page);

		inline_addr = inline_xattr_addr(inode, page);
	}
	memcpy(txattr_addr, inline_addr, inline_size);
	nbfs_put_page(page, 1);

	return 0;
}

static int read_xattr_block(struct inode *inode, void *txattr_addr)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	nid_t xnid = NBFS_I(inode)->i_xattr_nid;
	unsigned int inline_size = inline_xattr_size(inode);
	struct page *xpage;
	void *xattr_addr;

	/* The inode already has an extended attribute block. */
	xpage = nbfs_get_node_page(sbi, xnid);
	if (IS_ERR(xpage))
		return PTR_ERR(xpage);

	xattr_addr = page_address(xpage);
	memcpy(txattr_addr + inline_size, xattr_addr, VALID_XATTR_BLOCK_SIZE);
	nbfs_put_page(xpage, 1);

	return 0;
}

static int lookup_all_xattrs(struct inode *inode, struct page *ipage,
				unsigned int index, unsigned int len,
				const char *name, struct nbfs_xattr_entry **xe,
				void **base_addr, int *base_size)
{
	void *cur_addr, *txattr_addr, *last_addr = NULL;
	nid_t xnid = NBFS_I(inode)->i_xattr_nid;
	unsigned int size = xnid ? VALID_XATTR_BLOCK_SIZE : 0;
	unsigned int inline_size = inline_xattr_size(inode);
	int err = 0;

	if (!size && !inline_size)
		return -ENODATA;

	*base_size = inline_size + size + XATTR_PADDING_SIZE;
	txattr_addr = nbfs_kzalloc(NBFS_I_SB(inode), *base_size, GFP_NOFS);
	if (!txattr_addr)
		return -ENOMEM;

	/* read from inline xattr */
	if (inline_size) {
		err = read_inline_xattr(inode, ipage, txattr_addr);
		if (err)
			goto out;

		*xe = __find_inline_xattr(inode, txattr_addr, &last_addr,
						index, len, name);
		if (*xe) {
			*base_size = inline_size;
			goto check;
		}
	}

	/* read from xattr node block */
	if (xnid) {
		err = read_xattr_block(inode, txattr_addr);
		if (err)
			goto out;
	}

	if (last_addr)
		cur_addr = XATTR_HDR(last_addr) - 1;
	else
		cur_addr = txattr_addr;

	*xe = __find_xattr(cur_addr, index, len, name);
check:
	if (IS_XATTR_LAST_ENTRY(*xe)) {
		err = -ENODATA;
		goto out;
	}

	*base_addr = txattr_addr;
	return 0;
out:
	kvfree(txattr_addr);
	return err;
}

static int read_all_xattrs(struct inode *inode, struct page *ipage,
							void **base_addr)
{
	struct nbfs_xattr_header *header;
	nid_t xnid = NBFS_I(inode)->i_xattr_nid;
	unsigned int size = VALID_XATTR_BLOCK_SIZE;
	unsigned int inline_size = inline_xattr_size(inode);
	void *txattr_addr;
	int err;

	txattr_addr = nbfs_kzalloc(NBFS_I_SB(inode),
			inline_size + size + XATTR_PADDING_SIZE, GFP_NOFS);
	if (!txattr_addr)
		return -ENOMEM;

	/* read from inline xattr */
	if (inline_size) {
		err = read_inline_xattr(inode, ipage, txattr_addr);
		if (err)
			goto fail;
	}

	/* read from xattr node block */
	if (xnid) {
		err = read_xattr_block(inode, txattr_addr);
		if (err)
			goto fail;
	}

	header = XATTR_HDR(txattr_addr);

	/* never been allocated xattrs */
	if (le32_to_cpu(header->h_magic) != NBFS_XATTR_MAGIC) {
		header->h_magic = cpu_to_le32(NBFS_XATTR_MAGIC);
		header->h_refcount = cpu_to_le32(1);
	}
	*base_addr = txattr_addr;
	return 0;
fail:
	kvfree(txattr_addr);
	return err;
}

static inline int write_all_xattrs(struct inode *inode, __u32 hsize,
				void *txattr_addr, struct page *ipage)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	size_t inline_size = inline_xattr_size(inode);
	struct page *in_page = NULL;
	void *xattr_addr;
	void *inline_addr = NULL;
	struct page *xpage;
	nid_t new_nid = 0;
	int err = 0;

	if (hsize > inline_size && !NBFS_I(inode)->i_xattr_nid)
		if (!nbfs_alloc_nid(sbi, &new_nid))
			return -ENOSPC;

	/* write to inline xattr */
	if (inline_size) {
		if (ipage) {
			inline_addr = inline_xattr_addr(inode, ipage);
		} else {
			in_page = nbfs_get_node_page(sbi, inode->i_ino);
			if (IS_ERR(in_page)) {
				nbfs_alloc_nid_failed(sbi, new_nid);
				return PTR_ERR(in_page);
			}
			inline_addr = inline_xattr_addr(inode, in_page);
		}

		nbfs_wait_on_page_writeback(ipage ? ipage : in_page,
							NODE, true, true);
		/* no need to use xattr node block */
		if (hsize <= inline_size) {
			err = nbfs_truncate_xattr_node(inode);
			nbfs_alloc_nid_failed(sbi, new_nid);
			if (err) {
				nbfs_put_page(in_page, 1);
				return err;
			}
			memcpy(inline_addr, txattr_addr, inline_size);
			set_page_dirty(ipage ? ipage : in_page);
			goto in_page_out;
		}
	}

	/* write to xattr node block */
	if (NBFS_I(inode)->i_xattr_nid) {
		xpage = nbfs_get_node_page(sbi, NBFS_I(inode)->i_xattr_nid);
		if (IS_ERR(xpage)) {
			err = PTR_ERR(xpage);
			nbfs_alloc_nid_failed(sbi, new_nid);
			goto in_page_out;
		}
		nbfs_bug_on(sbi, new_nid);
		nbfs_wait_on_page_writeback(xpage, NODE, true, true);
	} else {
		struct dnode_of_data dn;
		set_new_dnode(&dn, inode, NULL, NULL, new_nid);
		xpage = nbfs_new_node_page(&dn, XATTR_NODE_OFFSET);
		if (IS_ERR(xpage)) {
			err = PTR_ERR(xpage);
			nbfs_alloc_nid_failed(sbi, new_nid);
			goto in_page_out;
		}
		nbfs_alloc_nid_done(sbi, new_nid);
	}
	xattr_addr = page_address(xpage);

	if (inline_size)
		memcpy(inline_addr, txattr_addr, inline_size);
	memcpy(xattr_addr, txattr_addr + inline_size, VALID_XATTR_BLOCK_SIZE);

	if (inline_size)
		set_page_dirty(ipage ? ipage : in_page);
	set_page_dirty(xpage);

	nbfs_put_page(xpage, 1);
in_page_out:
	nbfs_put_page(in_page, 1);
	return err;
}

int nbfs_getxattr(struct inode *inode, int index, const char *name,
		void *buffer, size_t buffer_size, struct page *ipage)
{
	struct nbfs_xattr_entry *entry = NULL;
	int error = 0;
	unsigned int size, len;
	void *base_addr = NULL;
	int base_size;

	if (name == NULL)
		return -EINVAL;

	len = strlen(name);
	if (len > NBFS_NAME_LEN)
		return -ERANGE;

	down_read(&NBFS_I(inode)->i_xattr_sem);
	error = lookup_all_xattrs(inode, ipage, index, len, name,
				&entry, &base_addr, &base_size);
	up_read(&NBFS_I(inode)->i_xattr_sem);
	if (error)
		return error;

	size = le16_to_cpu(entry->e_value_size);

	if (buffer && size > buffer_size) {
		error = -ERANGE;
		goto out;
	}

	if (buffer) {
		char *pval = entry->e_name + entry->e_name_len;

		if (base_size - (pval - (char *)base_addr) < size) {
			error = -ERANGE;
			goto out;
		}
		memcpy(buffer, pval, size);
	}
	error = size;
out:
	kvfree(base_addr);
	return error;
}

ssize_t nbfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode = d_inode(dentry);
	struct nbfs_xattr_entry *entry;
	void *base_addr;
	int error = 0;
	size_t rest = buffer_size;

	down_read(&NBFS_I(inode)->i_xattr_sem);
	error = read_all_xattrs(inode, NULL, &base_addr);
	up_read(&NBFS_I(inode)->i_xattr_sem);
	if (error)
		return error;

	list_for_each_xattr(entry, base_addr) {
		const struct xattr_handler *handler =
			nbfs_xattr_handler(entry->e_name_index);
		const char *prefix;
		size_t prefix_len;
		size_t size;

		if (!handler || (handler->list && !handler->list(dentry)))
			continue;

		prefix = xattr_prefix(handler);
		prefix_len = strlen(prefix);
		size = prefix_len + entry->e_name_len + 1;
		if (buffer) {
			if (size > rest) {
				error = -ERANGE;
				goto cleanup;
			}
			memcpy(buffer, prefix, prefix_len);
			buffer += prefix_len;
			memcpy(buffer, entry->e_name, entry->e_name_len);
			buffer += entry->e_name_len;
			*buffer++ = 0;
		}
		rest -= size;
	}
	error = buffer_size - rest;
cleanup:
	kvfree(base_addr);
	return error;
}

static bool nbfs_xattr_value_same(struct nbfs_xattr_entry *entry,
					const void *value, size_t size)
{
	void *pval = entry->e_name + entry->e_name_len;

	return (le16_to_cpu(entry->e_value_size) == size) &&
					!memcmp(pval, value, size);
}

static int __nbfs_setxattr(struct inode *inode, int index,
			const char *name, const void *value, size_t size,
			struct page *ipage, int flags)
{
	struct nbfs_xattr_entry *here, *last;
	void *base_addr;
	int found, newsize;
	size_t len;
	__u32 new_hsize;
	int error = 0;

	if (name == NULL)
		return -EINVAL;

	if (value == NULL)
		size = 0;

	len = strlen(name);

	if (len > NBFS_NAME_LEN)
		return -ERANGE;

	if (size > MAX_VALUE_LEN(inode))
		return -E2BIG;

	error = read_all_xattrs(inode, ipage, &base_addr);
	if (error)
		return error;

	/* find entry with wanted name. */
	here = __find_xattr(base_addr, index, len, name);

	found = IS_XATTR_LAST_ENTRY(here) ? 0 : 1;

	if (found) {
		if ((flags & XATTR_CREATE)) {
			error = -EEXIST;
			goto exit;
		}

		if (value && nbfs_xattr_value_same(here, value, size))
			goto exit;
	} else if ((flags & XATTR_REPLACE)) {
		error = -ENODATA;
		goto exit;
	}

	last = here;
	while (!IS_XATTR_LAST_ENTRY(last))
		last = XATTR_NEXT_ENTRY(last);

	newsize = XATTR_ALIGN(sizeof(struct nbfs_xattr_entry) + len + size);

	/* 1. Check space */
	if (value) {
		int free;
		/*
		 * If value is NULL, it is remove operation.
		 * In case of update operation, we calculate free.
		 */
		free = MIN_OFFSET(inode) - ((char *)last - (char *)base_addr);
		if (found)
			free = free + ENTRY_SIZE(here);

		if (unlikely(free < newsize)) {
			error = -E2BIG;
			goto exit;
		}
	}

	/* 2. Remove old entry */
	if (found) {
		/*
		 * If entry is found, remove old entry.
		 * If not found, remove operation is not needed.
		 */
		struct nbfs_xattr_entry *next = XATTR_NEXT_ENTRY(here);
		int oldsize = ENTRY_SIZE(here);

		memmove(here, next, (char *)last - (char *)next);
		last = (struct nbfs_xattr_entry *)((char *)last - oldsize);
		memset(last, 0, oldsize);
	}

	new_hsize = (char *)last - (char *)base_addr;

	/* 3. Write new entry */
	if (value) {
		char *pval;
		/*
		 * Before we come here, old entry is removed.
		 * We just write new entry.
		 */
		last->e_name_index = index;
		last->e_name_len = len;
		memcpy(last->e_name, name, len);
		pval = last->e_name + len;
		memcpy(pval, value, size);
		last->e_value_size = cpu_to_le16(size);
		new_hsize += newsize;
	}

	error = write_all_xattrs(inode, new_hsize, base_addr, ipage);
	if (error)
		goto exit;

	if (is_inode_flag_set(inode, FI_ACL_MODE)) {
		inode->i_mode = NBFS_I(inode)->i_acl_mode;
		inode->i_ctime = current_time(inode);
		clear_inode_flag(inode, FI_ACL_MODE);
	}
	if (index == NBFS_XATTR_INDEX_ENCRYPTION &&
			!strcmp(name, NBFS_XATTR_NAME_ENCRYPTION_CONTEXT))
		nbfs_set_encrypted_inode(inode);
	nbfs_mark_inode_dirty_sync(inode, true);
	if (!error && S_ISDIR(inode->i_mode))
		set_sbi_flag(NBFS_I_SB(inode), SBI_NEED_CP);
exit:
	kvfree(base_addr);
	return error;
}

int nbfs_setxattr(struct inode *inode, int index, const char *name,
				const void *value, size_t size,
				struct page *ipage, int flags)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	int err;

	err = dquot_initialize(inode);
	if (err)
		return err;

	/* this case is only from nbfs_init_inode_metadata */
	if (ipage)
		return __nbfs_setxattr(inode, index, name, value,
						size, ipage, flags);
	nbfs_balance_fs(sbi, true);

	nbfs_lock_op(sbi);
	/* protect xattr_ver */
	down_write(&NBFS_I(inode)->i_sem);
	down_write(&NBFS_I(inode)->i_xattr_sem);
	err = __nbfs_setxattr(inode, index, name, value, size, ipage, flags);
	up_write(&NBFS_I(inode)->i_xattr_sem);
	up_write(&NBFS_I(inode)->i_sem);
	nbfs_unlock_op(sbi);

	nbfs_update_time(sbi, REQ_TIME);
	return err;
}
