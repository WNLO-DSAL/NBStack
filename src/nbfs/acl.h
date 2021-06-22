// SPDX-License-Identifier: GPL-2.0
/*
 * fs/nbfs/acl.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Portions of this code from linux/fs/ext2/acl.h
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 */
#ifndef __NBFS_ACL_H__
#define __NBFS_ACL_H__

#include <linux/posix_acl_xattr.h>

#define NBFS_ACL_VERSION	0x0001

struct nbfs_acl_entry {
	__le16 e_tag;
	__le16 e_perm;
	__le32 e_id;
};

struct nbfs_acl_entry_short {
	__le16 e_tag;
	__le16 e_perm;
};

struct nbfs_acl_header {
	__le32 a_version;
};

#ifdef CONFIG_NBFS_FS_POSIX_ACL

extern struct posix_acl *nbfs_get_acl(struct inode *, int);
extern int nbfs_set_acl(struct inode *, struct posix_acl *, int);
extern int nbfs_init_acl(struct inode *, struct inode *, struct page *,
							struct page *);
#else
#define nbfs_get_acl	NULL
#define nbfs_set_acl	NULL

static inline int nbfs_init_acl(struct inode *inode, struct inode *dir,
				struct page *ipage, struct page *dpage)
{
	return 0;
}
#endif
#endif /* __NBFS_ACL_H__ */
