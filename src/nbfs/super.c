// SPDX-License-Identifier: GPL-2.0
/*
 * fs/nbfs/super.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/statfs.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>
#include <linux/kthread.h>
#include <linux/parser.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/exportfs.h>
#include <linux/blkdev.h>
#include <linux/quotaops.h>
#include <linux/nbfs_fs.h>
#include <linux/sysfs.h>
#include <linux/quota.h>
#include <linux/lightnvm.h>

#include "nbfs.h"
#include "node.h"
#include "segment.h"
#include "xattr.h"
#include "gc.h"
#include "trace.h"

#define CREATE_TRACE_POINTS
#include <trace/events/nbfs.h>

static struct kmem_cache *nbfs_inode_cachep;

#ifdef CONFIG_NBFS_FAULT_INJECTION

const char *nbfs_fault_name[FAULT_MAX] = {
	[FAULT_KMALLOC]		= "kmalloc",
	[FAULT_KVMALLOC]	= "kvmalloc",
	[FAULT_PAGE_ALLOC]	= "page alloc",
	[FAULT_PAGE_GET]	= "page get",
	[FAULT_ALLOC_BIO]	= "alloc bio",
	[FAULT_ALLOC_NID]	= "alloc nid",
	[FAULT_ORPHAN]		= "orphan",
	[FAULT_BLOCK]		= "no more block",
	[FAULT_DIR_DEPTH]	= "too big dir depth",
	[FAULT_EVICT_INODE]	= "evict_inode fail",
	[FAULT_TRUNCATE]	= "truncate fail",
	[FAULT_READ_IO]		= "read IO error",
	[FAULT_CHECKPOINT]	= "checkpoint error",
	[FAULT_DISCARD]		= "discard error",
	[FAULT_WRITE_IO]	= "write IO error",
};

void nbfs_build_fault_attr(struct nbfs_sb_info *sbi, unsigned int rate,
							unsigned int type)
{
	struct nbfs_fault_info *ffi = &NBFS_OPTION(sbi).fault_info;

	if (rate) {
		atomic_set(&ffi->inject_ops, 0);
		ffi->inject_rate = rate;
	}

	if (type)
		ffi->inject_type = type;

	if (!rate && !type)
		memset(ffi, 0, sizeof(struct nbfs_fault_info));
}
#endif

/* nbfs-wide shrinker description */
static struct shrinker nbfs_shrinker_info = {
	.scan_objects = nbfs_shrink_scan,
	.count_objects = nbfs_shrink_count,
	.seeks = DEFAULT_SEEKS,
};

enum {
	Opt_gc_background,
	Opt_disable_roll_forward,
	Opt_norecovery,
	Opt_discard,
	Opt_nodiscard,
	Opt_noheap,
	Opt_heap,
	Opt_user_xattr,
	Opt_nouser_xattr,
	Opt_acl,
	Opt_noacl,
	Opt_active_logs,
	Opt_disable_ext_identify,
	Opt_inline_xattr,
	Opt_noinline_xattr,
	Opt_inline_xattr_size,
	Opt_inline_data,
	Opt_inline_dentry,
	Opt_noinline_dentry,
	Opt_flush_merge,
	Opt_noflush_merge,
	Opt_nobarrier,
	Opt_fastboot,
	Opt_extent_cache,
	Opt_noextent_cache,
	Opt_noinline_data,
	Opt_data_flush,
	Opt_reserve_root,
	Opt_resgid,
	Opt_resuid,
	Opt_mode,
	Opt_io_size_bits,
	Opt_fault_injection,
	Opt_fault_type,
	Opt_lazytime,
	Opt_nolazytime,
	Opt_quota,
	Opt_noquota,
	Opt_usrquota,
	Opt_grpquota,
	Opt_prjquota,
	Opt_usrjquota,
	Opt_grpjquota,
	Opt_prjjquota,
	Opt_offusrjquota,
	Opt_offgrpjquota,
	Opt_offprjjquota,
	Opt_jqfmt_vfsold,
	Opt_jqfmt_vfsv0,
	Opt_jqfmt_vfsv1,
	Opt_whint,
	Opt_alloc,
	Opt_fsync,
	Opt_test_dummy_encryption,
	Opt_checkpoint,
	Opt_err,
};

static match_table_t nbfs_tokens = {
	{Opt_gc_background, "background_gc=%s"},
	{Opt_disable_roll_forward, "disable_roll_forward"},
	{Opt_norecovery, "norecovery"},
	{Opt_discard, "discard"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_noheap, "no_heap"},
	{Opt_heap, "heap"},
	{Opt_user_xattr, "user_xattr"},
	{Opt_nouser_xattr, "nouser_xattr"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_active_logs, "active_logs=%u"},
	{Opt_disable_ext_identify, "disable_ext_identify"},
	{Opt_inline_xattr, "inline_xattr"},
	{Opt_noinline_xattr, "noinline_xattr"},
	{Opt_inline_xattr_size, "inline_xattr_size=%u"},
	{Opt_inline_data, "inline_data"},
	{Opt_inline_dentry, "inline_dentry"},
	{Opt_noinline_dentry, "noinline_dentry"},
	{Opt_flush_merge, "flush_merge"},
	{Opt_noflush_merge, "noflush_merge"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_fastboot, "fastboot"},
	{Opt_extent_cache, "extent_cache"},
	{Opt_noextent_cache, "noextent_cache"},
	{Opt_noinline_data, "noinline_data"},
	{Opt_data_flush, "data_flush"},
	{Opt_reserve_root, "reserve_root=%u"},
	{Opt_resgid, "resgid=%u"},
	{Opt_resuid, "resuid=%u"},
	{Opt_mode, "mode=%s"},
	{Opt_io_size_bits, "io_bits=%u"},
	{Opt_fault_injection, "fault_injection=%u"},
	{Opt_fault_type, "fault_type=%u"},
	{Opt_lazytime, "lazytime"},
	{Opt_nolazytime, "nolazytime"},
	{Opt_quota, "quota"},
	{Opt_noquota, "noquota"},
	{Opt_usrquota, "usrquota"},
	{Opt_grpquota, "grpquota"},
	{Opt_prjquota, "prjquota"},
	{Opt_usrjquota, "usrjquota=%s"},
	{Opt_grpjquota, "grpjquota=%s"},
	{Opt_prjjquota, "prjjquota=%s"},
	{Opt_offusrjquota, "usrjquota="},
	{Opt_offgrpjquota, "grpjquota="},
	{Opt_offprjjquota, "prjjquota="},
	{Opt_jqfmt_vfsold, "jqfmt=vfsold"},
	{Opt_jqfmt_vfsv0, "jqfmt=vfsv0"},
	{Opt_jqfmt_vfsv1, "jqfmt=vfsv1"},
	{Opt_whint, "whint_mode=%s"},
	{Opt_alloc, "alloc_mode=%s"},
	{Opt_fsync, "fsync_mode=%s"},
	{Opt_test_dummy_encryption, "test_dummy_encryption"},
	{Opt_checkpoint, "checkpoint=%s"},
	{Opt_err, NULL},
};

void nbfs_msg(struct super_block *sb, const char *level, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%sNBFS-fs (%s): %pV\n", level, sb->s_id, &vaf);
	va_end(args);
}

static inline void limit_reserve_root(struct nbfs_sb_info *sbi)
{
	block_t limit = (sbi->user_block_count << 1) / 1000;

	/* limit is 0.2% */
	if (test_opt(sbi, RESERVE_ROOT) &&
			NBFS_OPTION(sbi).root_reserved_blocks > limit) {
		NBFS_OPTION(sbi).root_reserved_blocks = limit;
		nbfs_msg(sbi->sb, KERN_INFO,
			"Reduce reserved blocks for root = %u",
			NBFS_OPTION(sbi).root_reserved_blocks);
	}
	if (!test_opt(sbi, RESERVE_ROOT) &&
		(!uid_eq(NBFS_OPTION(sbi).s_resuid,
				make_kuid(&init_user_ns, NBFS_DEF_RESUID)) ||
		!gid_eq(NBFS_OPTION(sbi).s_resgid,
				make_kgid(&init_user_ns, NBFS_DEF_RESGID))))
		nbfs_msg(sbi->sb, KERN_INFO,
			"Ignore s_resuid=%u, s_resgid=%u w/o reserve_root",
				from_kuid_munged(&init_user_ns,
					NBFS_OPTION(sbi).s_resuid),
				from_kgid_munged(&init_user_ns,
					NBFS_OPTION(sbi).s_resgid));
}

static void init_once(void *foo)
{
	struct nbfs_inode_info *fi = (struct nbfs_inode_info *) foo;

	inode_init_once(&fi->vfs_inode);
}

#ifdef CONFIG_QUOTA
static const char * const quotatypes[] = INITQFNAMES;
#define QTYPE2NAME(t) (quotatypes[t])
static int nbfs_set_qf_name(struct super_block *sb, int qtype,
							substring_t *args)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	char *qname;
	int ret = -EINVAL;

	if (sb_any_quota_loaded(sb) && !NBFS_OPTION(sbi).s_qf_names[qtype]) {
		nbfs_msg(sb, KERN_ERR,
			"Cannot change journaled "
			"quota options when quota turned on");
		return -EINVAL;
	}
	if (nbfs_sb_has_quota_ino(sbi)) {
		nbfs_msg(sb, KERN_INFO,
			"QUOTA feature is enabled, so ignore qf_name");
		return 0;
	}

	qname = match_strdup(args);
	if (!qname) {
		nbfs_msg(sb, KERN_ERR,
			"Not enough memory for storing quotafile name");
		return -ENOMEM;
	}
	if (NBFS_OPTION(sbi).s_qf_names[qtype]) {
		if (strcmp(NBFS_OPTION(sbi).s_qf_names[qtype], qname) == 0)
			ret = 0;
		else
			nbfs_msg(sb, KERN_ERR,
				 "%s quota file already specified",
				 QTYPE2NAME(qtype));
		goto errout;
	}
	if (strchr(qname, '/')) {
		nbfs_msg(sb, KERN_ERR,
			"quotafile must be on filesystem root");
		goto errout;
	}
	NBFS_OPTION(sbi).s_qf_names[qtype] = qname;
	set_opt(sbi, QUOTA);
	return 0;
errout:
	kvfree(qname);
	return ret;
}

static int nbfs_clear_qf_name(struct super_block *sb, int qtype)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);

	if (sb_any_quota_loaded(sb) && NBFS_OPTION(sbi).s_qf_names[qtype]) {
		nbfs_msg(sb, KERN_ERR, "Cannot change journaled quota options"
			" when quota turned on");
		return -EINVAL;
	}
	kvfree(NBFS_OPTION(sbi).s_qf_names[qtype]);
	NBFS_OPTION(sbi).s_qf_names[qtype] = NULL;
	return 0;
}

static int nbfs_check_quota_options(struct nbfs_sb_info *sbi)
{
	/*
	 * We do the test below only for project quotas. 'usrquota' and
	 * 'grpquota' mount options are allowed even without quota feature
	 * to support legacy quotas in quota files.
	 */
	if (test_opt(sbi, PRJQUOTA) && !nbfs_sb_has_project_quota(sbi)) {
		nbfs_msg(sbi->sb, KERN_ERR, "Project quota feature not enabled. "
			 "Cannot enable project quota enforcement.");
		return -1;
	}
	if (NBFS_OPTION(sbi).s_qf_names[USRQUOTA] ||
			NBFS_OPTION(sbi).s_qf_names[GRPQUOTA] ||
			NBFS_OPTION(sbi).s_qf_names[PRJQUOTA]) {
		if (test_opt(sbi, USRQUOTA) &&
				NBFS_OPTION(sbi).s_qf_names[USRQUOTA])
			clear_opt(sbi, USRQUOTA);

		if (test_opt(sbi, GRPQUOTA) &&
				NBFS_OPTION(sbi).s_qf_names[GRPQUOTA])
			clear_opt(sbi, GRPQUOTA);

		if (test_opt(sbi, PRJQUOTA) &&
				NBFS_OPTION(sbi).s_qf_names[PRJQUOTA])
			clear_opt(sbi, PRJQUOTA);

		if (test_opt(sbi, GRPQUOTA) || test_opt(sbi, USRQUOTA) ||
				test_opt(sbi, PRJQUOTA)) {
			nbfs_msg(sbi->sb, KERN_ERR, "old and new quota "
					"format mixing");
			return -1;
		}

		if (!NBFS_OPTION(sbi).s_jquota_fmt) {
			nbfs_msg(sbi->sb, KERN_ERR, "journaled quota format "
					"not specified");
			return -1;
		}
	}

	if (nbfs_sb_has_quota_ino(sbi) && NBFS_OPTION(sbi).s_jquota_fmt) {
		nbfs_msg(sbi->sb, KERN_INFO,
			"QUOTA feature is enabled, so ignore jquota_fmt");
		NBFS_OPTION(sbi).s_jquota_fmt = 0;
	}
	return 0;
}
#endif

static int parse_options(struct super_block *sb, char *options)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	substring_t args[MAX_OPT_ARGS];
	char *p, *name;
	int arg = 0;
	kuid_t uid;
	kgid_t gid;
#ifdef CONFIG_QUOTA
	int ret;
#endif

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;
		/*
		 * Initialize args struct so we know whether arg was
		 * found; some options take optional arguments.
		 */
		args[0].to = args[0].from = NULL;
		token = match_token(p, nbfs_tokens, args);

		switch (token) {
		case Opt_gc_background:
			name = match_strdup(&args[0]);

			if (!name)
				return -ENOMEM;
			if (strlen(name) == 2 && !strncmp(name, "on", 2)) {
				set_opt(sbi, BG_GC);
				clear_opt(sbi, FORCE_FG_GC);
			} else if (strlen(name) == 3 && !strncmp(name, "off", 3)) {
				clear_opt(sbi, BG_GC);
				clear_opt(sbi, FORCE_FG_GC);
			} else if (strlen(name) == 4 && !strncmp(name, "sync", 4)) {
				set_opt(sbi, BG_GC);
				set_opt(sbi, FORCE_FG_GC);
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_disable_roll_forward:
			set_opt(sbi, DISABLE_ROLL_FORWARD);
			break;
		case Opt_norecovery:
			/* this option mounts nbfs with ro */
			set_opt(sbi, DISABLE_ROLL_FORWARD);
			if (!nbfs_readonly(sb))
				return -EINVAL;
			break;
		case Opt_discard:
			set_opt(sbi, DISCARD);
			break;
		case Opt_nodiscard:
			if (nbfs_sb_has_blkzoned(sbi)) {
				nbfs_msg(sb, KERN_WARNING,
					"discard is required for zoned block devices");
				return -EINVAL;
			}
			clear_opt(sbi, DISCARD);
			break;
		case Opt_noheap:
			set_opt(sbi, NOHEAP);
			break;
		case Opt_heap:
			clear_opt(sbi, NOHEAP);
			break;
#ifdef CONFIG_NBFS_FS_XATTR
		case Opt_user_xattr:
			set_opt(sbi, XATTR_USER);
			break;
		case Opt_nouser_xattr:
			clear_opt(sbi, XATTR_USER);
			break;
		case Opt_inline_xattr:
			set_opt(sbi, INLINE_XATTR);
			break;
		case Opt_noinline_xattr:
			clear_opt(sbi, INLINE_XATTR);
			break;
		case Opt_inline_xattr_size:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			set_opt(sbi, INLINE_XATTR_SIZE);
			NBFS_OPTION(sbi).inline_xattr_size = arg;
			break;
#else
		case Opt_user_xattr:
			nbfs_msg(sb, KERN_INFO,
				"user_xattr options not supported");
			break;
		case Opt_nouser_xattr:
			nbfs_msg(sb, KERN_INFO,
				"nouser_xattr options not supported");
			break;
		case Opt_inline_xattr:
			nbfs_msg(sb, KERN_INFO,
				"inline_xattr options not supported");
			break;
		case Opt_noinline_xattr:
			nbfs_msg(sb, KERN_INFO,
				"noinline_xattr options not supported");
			break;
#endif
#ifdef CONFIG_NBFS_FS_POSIX_ACL
		case Opt_acl:
			set_opt(sbi, POSIX_ACL);
			break;
		case Opt_noacl:
			clear_opt(sbi, POSIX_ACL);
			break;
#else
		case Opt_acl:
			nbfs_msg(sb, KERN_INFO, "acl options not supported");
			break;
		case Opt_noacl:
			nbfs_msg(sb, KERN_INFO, "noacl options not supported");
			break;
#endif
		case Opt_active_logs:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			if (arg != 2 && arg != 4 && arg != NR_CURSEG_TYPE)
				return -EINVAL;
			NBFS_OPTION(sbi).active_logs = arg;
			break;
		case Opt_disable_ext_identify:
			set_opt(sbi, DISABLE_EXT_IDENTIFY);
			break;
		case Opt_inline_data:
			set_opt(sbi, INLINE_DATA);
			break;
		case Opt_inline_dentry:
			set_opt(sbi, INLINE_DENTRY);
			break;
		case Opt_noinline_dentry:
			clear_opt(sbi, INLINE_DENTRY);
			break;
		case Opt_flush_merge:
			set_opt(sbi, FLUSH_MERGE);
			break;
		case Opt_noflush_merge:
			clear_opt(sbi, FLUSH_MERGE);
			break;
		case Opt_nobarrier:
			set_opt(sbi, NOBARRIER);
			break;
		case Opt_fastboot:
			set_opt(sbi, FASTBOOT);
			break;
		case Opt_extent_cache:
			set_opt(sbi, EXTENT_CACHE);
			break;
		case Opt_noextent_cache:
			clear_opt(sbi, EXTENT_CACHE);
			break;
		case Opt_noinline_data:
			clear_opt(sbi, INLINE_DATA);
			break;
		case Opt_data_flush:
			set_opt(sbi, DATA_FLUSH);
			break;
		case Opt_reserve_root:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			if (test_opt(sbi, RESERVE_ROOT)) {
				nbfs_msg(sb, KERN_INFO,
					"Preserve previous reserve_root=%u",
					NBFS_OPTION(sbi).root_reserved_blocks);
			} else {
				NBFS_OPTION(sbi).root_reserved_blocks = arg;
				set_opt(sbi, RESERVE_ROOT);
			}
			break;
		case Opt_resuid:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			uid = make_kuid(current_user_ns(), arg);
			if (!uid_valid(uid)) {
				nbfs_msg(sb, KERN_ERR,
					"Invalid uid value %d", arg);
				return -EINVAL;
			}
			NBFS_OPTION(sbi).s_resuid = uid;
			break;
		case Opt_resgid:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			gid = make_kgid(current_user_ns(), arg);
			if (!gid_valid(gid)) {
				nbfs_msg(sb, KERN_ERR,
					"Invalid gid value %d", arg);
				return -EINVAL;
			}
			NBFS_OPTION(sbi).s_resgid = gid;
			break;
		case Opt_mode:
			name = match_strdup(&args[0]);

			if (!name)
				return -ENOMEM;
			if (strlen(name) == 8 &&
					!strncmp(name, "adaptive", 8)) {
				if (nbfs_sb_has_blkzoned(sbi)) {
					nbfs_msg(sb, KERN_WARNING,
						 "adaptive mode is not allowed with "
						 "zoned block device feature");
					kvfree(name);
					return -EINVAL;
				}
				set_opt_mode(sbi, NBFS_MOUNT_ADAPTIVE);
			} else if (strlen(name) == 3 &&
					!strncmp(name, "lfs", 3)) {
				set_opt_mode(sbi, NBFS_MOUNT_LFS);
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_io_size_bits:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			if (arg <= 0 || arg > __ilog2_u32(BIO_MAX_PAGES)) {
				nbfs_msg(sb, KERN_WARNING,
					"Not support %d, larger than %d",
					1 << arg, BIO_MAX_PAGES);
				return -EINVAL;
			}
			NBFS_OPTION(sbi).write_io_size_bits = arg;
			break;
#ifdef CONFIG_NBFS_FAULT_INJECTION
		case Opt_fault_injection:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			nbfs_build_fault_attr(sbi, arg, NBFS_ALL_FAULT_TYPE);
			set_opt(sbi, FAULT_INJECTION);
			break;

		case Opt_fault_type:
			if (args->from && match_int(args, &arg))
				return -EINVAL;
			nbfs_build_fault_attr(sbi, 0, arg);
			set_opt(sbi, FAULT_INJECTION);
			break;
#else
		case Opt_fault_injection:
			nbfs_msg(sb, KERN_INFO,
				"fault_injection options not supported");
			break;

		case Opt_fault_type:
			nbfs_msg(sb, KERN_INFO,
				"fault_type options not supported");
			break;
#endif
		case Opt_lazytime:
			sb->s_flags |= SB_LAZYTIME;
			break;
		case Opt_nolazytime:
			sb->s_flags &= ~SB_LAZYTIME;
			break;
#ifdef CONFIG_QUOTA
		case Opt_quota:
		case Opt_usrquota:
			set_opt(sbi, USRQUOTA);
			break;
		case Opt_grpquota:
			set_opt(sbi, GRPQUOTA);
			break;
		case Opt_prjquota:
			set_opt(sbi, PRJQUOTA);
			break;
		case Opt_usrjquota:
			ret = nbfs_set_qf_name(sb, USRQUOTA, &args[0]);
			if (ret)
				return ret;
			break;
		case Opt_grpjquota:
			ret = nbfs_set_qf_name(sb, GRPQUOTA, &args[0]);
			if (ret)
				return ret;
			break;
		case Opt_prjjquota:
			ret = nbfs_set_qf_name(sb, PRJQUOTA, &args[0]);
			if (ret)
				return ret;
			break;
		case Opt_offusrjquota:
			ret = nbfs_clear_qf_name(sb, USRQUOTA);
			if (ret)
				return ret;
			break;
		case Opt_offgrpjquota:
			ret = nbfs_clear_qf_name(sb, GRPQUOTA);
			if (ret)
				return ret;
			break;
		case Opt_offprjjquota:
			ret = nbfs_clear_qf_name(sb, PRJQUOTA);
			if (ret)
				return ret;
			break;
		case Opt_jqfmt_vfsold:
			NBFS_OPTION(sbi).s_jquota_fmt = QFMT_VFS_OLD;
			break;
		case Opt_jqfmt_vfsv0:
			NBFS_OPTION(sbi).s_jquota_fmt = QFMT_VFS_V0;
			break;
		case Opt_jqfmt_vfsv1:
			NBFS_OPTION(sbi).s_jquota_fmt = QFMT_VFS_V1;
			break;
		case Opt_noquota:
			clear_opt(sbi, QUOTA);
			clear_opt(sbi, USRQUOTA);
			clear_opt(sbi, GRPQUOTA);
			clear_opt(sbi, PRJQUOTA);
			break;
#else
		case Opt_quota:
		case Opt_usrquota:
		case Opt_grpquota:
		case Opt_prjquota:
		case Opt_usrjquota:
		case Opt_grpjquota:
		case Opt_prjjquota:
		case Opt_offusrjquota:
		case Opt_offgrpjquota:
		case Opt_offprjjquota:
		case Opt_jqfmt_vfsold:
		case Opt_jqfmt_vfsv0:
		case Opt_jqfmt_vfsv1:
		case Opt_noquota:
			nbfs_msg(sb, KERN_INFO,
					"quota operations not supported");
			break;
#endif
		case Opt_whint:
			name = match_strdup(&args[0]);
			if (!name)
				return -ENOMEM;
			if (strlen(name) == 10 &&
					!strncmp(name, "user-based", 10)) {
				NBFS_OPTION(sbi).whint_mode = WHINT_MODE_USER;
			} else if (strlen(name) == 3 &&
					!strncmp(name, "off", 3)) {
				NBFS_OPTION(sbi).whint_mode = WHINT_MODE_OFF;
			} else if (strlen(name) == 8 &&
					!strncmp(name, "fs-based", 8)) {
				NBFS_OPTION(sbi).whint_mode = WHINT_MODE_FS;
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_alloc:
			name = match_strdup(&args[0]);
			if (!name)
				return -ENOMEM;

			if (strlen(name) == 7 &&
					!strncmp(name, "default", 7)) {
				NBFS_OPTION(sbi).alloc_mode = ALLOC_MODE_DEFAULT;
			} else if (strlen(name) == 5 &&
					!strncmp(name, "reuse", 5)) {
				NBFS_OPTION(sbi).alloc_mode = ALLOC_MODE_REUSE;
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_fsync:
			name = match_strdup(&args[0]);
			if (!name)
				return -ENOMEM;
			if (strlen(name) == 5 &&
					!strncmp(name, "posix", 5)) {
				NBFS_OPTION(sbi).fsync_mode = FSYNC_MODE_POSIX;
			} else if (strlen(name) == 6 &&
					!strncmp(name, "strict", 6)) {
				NBFS_OPTION(sbi).fsync_mode = FSYNC_MODE_STRICT;
			} else if (strlen(name) == 9 &&
					!strncmp(name, "nobarrier", 9)) {
				NBFS_OPTION(sbi).fsync_mode =
							FSYNC_MODE_NOBARRIER;
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		case Opt_test_dummy_encryption:
#ifdef CONFIG_FS_ENCRYPTION
			if (!nbfs_sb_has_encrypt(sbi)) {
				nbfs_msg(sb, KERN_ERR, "Encrypt feature is off");
				return -EINVAL;
			}

			NBFS_OPTION(sbi).test_dummy_encryption = true;
			nbfs_msg(sb, KERN_INFO,
					"Test dummy encryption mode enabled");
#else
			nbfs_msg(sb, KERN_INFO,
					"Test dummy encryption mount option ignored");
#endif
			break;
		case Opt_checkpoint:
			name = match_strdup(&args[0]);
			if (!name)
				return -ENOMEM;

			if (strlen(name) == 6 &&
					!strncmp(name, "enable", 6)) {
				clear_opt(sbi, DISABLE_CHECKPOINT);
			} else if (strlen(name) == 7 &&
					!strncmp(name, "disable", 7)) {
				set_opt(sbi, DISABLE_CHECKPOINT);
			} else {
				kvfree(name);
				return -EINVAL;
			}
			kvfree(name);
			break;
		default:
			nbfs_msg(sb, KERN_ERR,
				"Unrecognized mount option \"%s\" or missing value",
				p);
			return -EINVAL;
		}
	}
#ifdef CONFIG_QUOTA
	if (nbfs_check_quota_options(sbi))
		return -EINVAL;
#else
	if (nbfs_sb_has_quota_ino(sbi) && !nbfs_readonly(sbi->sb)) {
		nbfs_msg(sbi->sb, KERN_INFO,
			 "Filesystem with quota feature cannot be mounted RDWR "
			 "without CONFIG_QUOTA");
		return -EINVAL;
	}
	if (nbfs_sb_has_project_quota(sbi) && !nbfs_readonly(sbi->sb)) {
		nbfs_msg(sb, KERN_ERR,
			"Filesystem with project quota feature cannot be "
			"mounted RDWR without CONFIG_QUOTA");
		return -EINVAL;
	}
#endif

	if (NBFS_IO_SIZE_BITS(sbi) && !test_opt(sbi, LFS)) {
		nbfs_msg(sb, KERN_ERR,
				"Should set mode=lfs with %uKB-sized IO",
				NBFS_IO_SIZE_KB(sbi));
		return -EINVAL;
	}

	if (test_opt(sbi, INLINE_XATTR_SIZE)) {
		int min_size, max_size;

		if (!nbfs_sb_has_extra_attr(sbi) ||
			!nbfs_sb_has_flexible_inline_xattr(sbi)) {
			nbfs_msg(sb, KERN_ERR,
					"extra_attr or flexible_inline_xattr "
					"feature is off");
			return -EINVAL;
		}
		if (!test_opt(sbi, INLINE_XATTR)) {
			nbfs_msg(sb, KERN_ERR,
					"inline_xattr_size option should be "
					"set with inline_xattr option");
			return -EINVAL;
		}

		min_size = sizeof(struct nbfs_xattr_header) / sizeof(__le32);
		max_size = MAX_INLINE_XATTR_SIZE;

		if (NBFS_OPTION(sbi).inline_xattr_size < min_size ||
				NBFS_OPTION(sbi).inline_xattr_size > max_size) {
			nbfs_msg(sb, KERN_ERR,
				"inline xattr size is out of range: %d ~ %d",
				min_size, max_size);
			return -EINVAL;
		}
	}

	if (test_opt(sbi, DISABLE_CHECKPOINT) && test_opt(sbi, LFS)) {
		nbfs_msg(sb, KERN_ERR,
				"LFS not compatible with checkpoint=disable\n");
		return -EINVAL;
	}

	/* Not pass down write hints if the number of active logs is lesser
	 * than NR_CURSEG_TYPE.
	 */
	if (NBFS_OPTION(sbi).active_logs != NR_CURSEG_TYPE)
		NBFS_OPTION(sbi).whint_mode = WHINT_MODE_OFF;
	return 0;
}

static struct inode *nbfs_alloc_inode(struct super_block *sb)
{
	struct nbfs_inode_info *fi;

	fi = kmem_cache_alloc(nbfs_inode_cachep, GFP_NBFS_ZERO);
	if (!fi)
		return NULL;

	init_once((void *) fi);

	/* Initialize nbfs-specific inode info */
	atomic_set(&fi->dirty_pages, 0);
	init_rwsem(&fi->i_sem);
	INIT_LIST_HEAD(&fi->dirty_list);
	INIT_LIST_HEAD(&fi->gdirty_list);
	INIT_LIST_HEAD(&fi->inmem_ilist);
	INIT_LIST_HEAD(&fi->inmem_pages);
	mutex_init(&fi->inmem_lock);
	init_rwsem(&fi->i_gc_rwsem[READ]);
	init_rwsem(&fi->i_gc_rwsem[WRITE]);
	init_rwsem(&fi->i_mmap_sem);
	init_rwsem(&fi->i_xattr_sem);

	INIT_LIST_HEAD(&fi->wb_node_list);
	spin_lock_init(&fi->wb_node_lock);

	/* Will be used by directory only */
	fi->i_dir_level = NBFS_SB(sb)->dir_level;

	return &fi->vfs_inode;
}

static int nbfs_drop_inode(struct inode *inode)
{
	int ret;
	/*
	 * This is to avoid a deadlock condition like below.
	 * writeback_single_inode(inode)
	 *  - nbfs_write_data_page
	 *    - nbfs_gc -> iput -> evict
	 *       - inode_wait_for_writeback(inode)
	 */
	if ((!inode_unhashed(inode) && inode->i_state & I_SYNC)) {
		if (!inode->i_nlink && !is_bad_inode(inode)) {
			/* to avoid evict_inode call simultaneously */
			atomic_inc(&inode->i_count);
			spin_unlock(&inode->i_lock);

			/* some remained atomic pages should discarded */
			if (nbfs_is_atomic_file(inode))
				nbfs_drop_inmem_pages(inode);

			/* should remain fi->extent_tree for writepage */
			nbfs_destroy_extent_node(inode);

			sb_start_intwrite(inode->i_sb);
			nbfs_i_size_write(inode, 0);

			nbfs_submit_merged_write_cond(NBFS_I_SB(inode),
					inode, NULL, 0, DATA);
			truncate_inode_pages_final(inode->i_mapping);

			if (NBFS_HAS_BLOCKS(inode))
				nbfs_truncate(inode);

			sb_end_intwrite(inode->i_sb);

			spin_lock(&inode->i_lock);
			atomic_dec(&inode->i_count);
		}
		trace_nbfs_drop_inode(inode, 0);
		return 0;
	}
	ret = generic_drop_inode(inode);
	trace_nbfs_drop_inode(inode, ret);
	return ret;
}

int nbfs_inode_dirtied(struct inode *inode, bool sync)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);
	int ret = 0;

	spin_lock(&sbi->inode_lock[DIRTY_META]);
	if (is_inode_flag_set(inode, FI_DIRTY_INODE)) {
		ret = 1;
	} else {
		set_inode_flag(inode, FI_DIRTY_INODE);
		stat_inc_dirty_inode(sbi, DIRTY_META);
	}
	if (sync && list_empty(&NBFS_I(inode)->gdirty_list)) {
		list_add_tail(&NBFS_I(inode)->gdirty_list,
				&sbi->inode_list[DIRTY_META]);
		inc_page_count(sbi, NBFS_DIRTY_IMETA);
	}
	spin_unlock(&sbi->inode_lock[DIRTY_META]);
	return ret;
}

void nbfs_inode_synced(struct inode *inode)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);

	spin_lock(&sbi->inode_lock[DIRTY_META]);
	if (!is_inode_flag_set(inode, FI_DIRTY_INODE)) {
		spin_unlock(&sbi->inode_lock[DIRTY_META]);
		return;
	}
	if (!list_empty(&NBFS_I(inode)->gdirty_list)) {
		list_del_init(&NBFS_I(inode)->gdirty_list);
		dec_page_count(sbi, NBFS_DIRTY_IMETA);
	}
	clear_inode_flag(inode, FI_DIRTY_INODE);
	clear_inode_flag(inode, FI_AUTO_RECOVER);
	stat_dec_dirty_inode(NBFS_I_SB(inode), DIRTY_META);
	spin_unlock(&sbi->inode_lock[DIRTY_META]);
}

/*
 * nbfs_dirty_inode() is called from __mark_inode_dirty()
 *
 * We should call set_dirty_inode to write the dirty inode through write_inode.
 */
static void nbfs_dirty_inode(struct inode *inode, int flags)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);

	if (inode->i_ino == NBFS_NODE_INO(sbi) ||
			inode->i_ino == NBFS_META_INO(sbi))
		return;

	if (flags == I_DIRTY_TIME)
		return;

	if (is_inode_flag_set(inode, FI_AUTO_RECOVER))
		clear_inode_flag(inode, FI_AUTO_RECOVER);

	nbfs_inode_dirtied(inode, false);
}

static void nbfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(nbfs_inode_cachep, NBFS_I(inode));
}

static void nbfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, nbfs_i_callback);
}

static void destroy_percpu_info(struct nbfs_sb_info *sbi)
{
	percpu_counter_destroy(&sbi->alloc_valid_block_count);
	percpu_counter_destroy(&sbi->total_valid_inode_count);
}

static void destroy_device_list(struct nbfs_sb_info *sbi)
{
	int i;

	for (i = 0; i < sbi->s_ndevs; i++) {
		blkdev_put(FDEV(i).bdev, FMODE_EXCL);
#ifdef CONFIG_BLK_DEV_ZONED
		kvfree(FDEV(i).blkz_type);
#endif
	}
	kvfree(sbi->devs);
}

static void nbfs_put_super(struct super_block *sb)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	int i;
	bool dropped;

	nbfs_quota_off_umount(sb);

	/* prevent remaining shrinker jobs */
	mutex_lock(&sbi->umount_mutex);

	/*
	 * We don't need to do checkpoint when superblock is clean.
	 * But, the previous checkpoint was not done by umount, it needs to do
	 * clean checkpoint again.
	 */
	if ((is_sbi_flag_set(sbi, SBI_IS_DIRTY) ||
			!is_set_ckpt_flags(sbi, CP_UMOUNT_FLAG))) {
		struct cp_control cpc = {
			.reason = CP_UMOUNT,
		};
		nbfs_write_checkpoint(sbi, &cpc);
	}

	/* be sure to wait for any on-going discard commands */
	dropped = nbfs_issue_discard_timeout(sbi);

	if ((nbfs_hw_support_discard(sbi) || nbfs_hw_should_discard(sbi)) &&
					!sbi->discard_blks && !dropped) {
		struct cp_control cpc = {
			.reason = CP_UMOUNT | CP_TRIMMED,
		};
		nbfs_write_checkpoint(sbi, &cpc);
	}

	/*
	 * normally superblock is clean, so we need to release this.
	 * In addition, EIO will skip do checkpoint, we need this as well.
	 */
	nbfs_release_ino_entry(sbi, true);

	nbfs_leave_shrinker(sbi);
	mutex_unlock(&sbi->umount_mutex);

	/* our cp_error case, we can wait for any writeback page */
	nbfs_flush_merged_writes(sbi);

	nbfs_wait_on_all_pages_writeback(sbi);

	nbfs_bug_on(sbi, sbi->fsync_node_num);

	iput(sbi->node_inode);
	sbi->node_inode = NULL;

	iput(sbi->meta_inode);
	sbi->meta_inode = NULL;

	/*
	 * iput() can update stat information, if nbfs_write_checkpoint()
	 * above failed with error.
	 */
	nbfs_destroy_stats(sbi);

	/* destroy nbfs internal modules */
	nbfs_destroy_node_manager(sbi);
	nbfs_destroy_segment_manager(sbi);

	kvfree(sbi->ckpt);

	nbfs_unregister_sysfs(sbi);

	sb->s_fs_info = NULL;
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);
	kvfree(sbi->raw_super);

	destroy_device_list(sbi);
	mempool_destroy(sbi->write_io_dummy);
#ifdef CONFIG_QUOTA
	for (i = 0; i < MAXQUOTAS; i++)
		kvfree(NBFS_OPTION(sbi).s_qf_names[i]);
#endif
	destroy_percpu_info(sbi);
	for (i = 0; i < NR_PAGE_TYPE; i++)
		kvfree(sbi->write_io[i]);
	kvfree(sbi);
}

int nbfs_sync_fs(struct super_block *sb, int sync)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	int err = 0;

	if (unlikely(nbfs_cp_error(sbi)))
		return 0;
	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return 0;

	trace_nbfs_sync_fs(sb, sync);

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		return -EAGAIN;

	if (sync) {
		struct cp_control cpc;

		cpc.reason = __get_cp_reason(sbi);

		mutex_lock(&sbi->gc_mutex);
		err = nbfs_write_checkpoint(sbi, &cpc);
		mutex_unlock(&sbi->gc_mutex);
	}
	nbfs_trace_ios(NULL, 1);

	return err;
}

static int nbfs_freeze(struct super_block *sb)
{
	if (nbfs_readonly(sb))
		return 0;

	/* IO error happened before */
	if (unlikely(nbfs_cp_error(NBFS_SB(sb))))
		return -EIO;

	/* must be clean, since sync_filesystem() was already called */
	if (is_sbi_flag_set(NBFS_SB(sb), SBI_IS_DIRTY))
		return -EINVAL;
	return 0;
}

static int nbfs_unfreeze(struct super_block *sb)
{
	return 0;
}

#ifdef CONFIG_QUOTA
static int nbfs_statfs_project(struct super_block *sb,
				kprojid_t projid, struct kstatfs *buf)
{
	struct kqid qid;
	struct dquot *dquot;
	u64 limit;
	u64 curblock;

	qid = make_kqid_projid(projid);
	dquot = dqget(sb, qid);
	if (IS_ERR(dquot))
		return PTR_ERR(dquot);
	spin_lock(&dquot->dq_dqb_lock);

	limit = (dquot->dq_dqb.dqb_bsoftlimit ?
		 dquot->dq_dqb.dqb_bsoftlimit :
		 dquot->dq_dqb.dqb_bhardlimit) >> sb->s_blocksize_bits;
	if (limit && buf->f_blocks > limit) {
		curblock = dquot->dq_dqb.dqb_curspace >> sb->s_blocksize_bits;
		buf->f_blocks = limit;
		buf->f_bfree = buf->f_bavail =
			(buf->f_blocks > curblock) ?
			 (buf->f_blocks - curblock) : 0;
	}

	limit = dquot->dq_dqb.dqb_isoftlimit ?
		dquot->dq_dqb.dqb_isoftlimit :
		dquot->dq_dqb.dqb_ihardlimit;
	if (limit && buf->f_files > limit) {
		buf->f_files = limit;
		buf->f_ffree =
			(buf->f_files > dquot->dq_dqb.dqb_curinodes) ?
			 (buf->f_files - dquot->dq_dqb.dqb_curinodes) : 0;
	}

	spin_unlock(&dquot->dq_dqb_lock);
	dqput(dquot);
	return 0;
}
#endif

static int nbfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
	block_t total_count, user_block_count, start_count;
	u64 avail_node_count;

	total_count = le64_to_cpu(sbi->raw_super->block_count);
	user_block_count = sbi->user_block_count;
	start_count = le32_to_cpu(sbi->raw_super->segment0_blkaddr);
	buf->f_type = F2FS_SUPER_MAGIC;
	buf->f_bsize = sbi->blocksize;

	buf->f_blocks = total_count - start_count;
	buf->f_bfree = user_block_count - valid_user_blocks(sbi) -
						sbi->current_reserved_blocks;
	if (unlikely(buf->f_bfree <= sbi->unusable_block_count))
		buf->f_bfree = 0;
	else
		buf->f_bfree -= sbi->unusable_block_count;

	if (buf->f_bfree > NBFS_OPTION(sbi).root_reserved_blocks)
		buf->f_bavail = buf->f_bfree -
				NBFS_OPTION(sbi).root_reserved_blocks;
	else
		buf->f_bavail = 0;

	avail_node_count = sbi->total_node_count - sbi->nquota_files -
						NBFS_RESERVED_NODE_NUM;

	if (avail_node_count > user_block_count) {
		buf->f_files = user_block_count;
		buf->f_ffree = buf->f_bavail;
	} else {
		buf->f_files = avail_node_count;
		buf->f_ffree = min(avail_node_count - valid_node_count(sbi),
					buf->f_bavail);
	}

	buf->f_namelen = NBFS_NAME_LEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

#ifdef CONFIG_QUOTA
	if (is_inode_flag_set(dentry->d_inode, FI_PROJ_INHERIT) &&
			sb_has_quota_limits_enabled(sb, PRJQUOTA)) {
		nbfs_statfs_project(sb, NBFS_I(dentry->d_inode)->i_projid, buf);
	}
#endif
	return 0;
}

static inline void nbfs_show_quota_options(struct seq_file *seq,
					   struct super_block *sb)
{
#ifdef CONFIG_QUOTA
	struct nbfs_sb_info *sbi = NBFS_SB(sb);

	if (NBFS_OPTION(sbi).s_jquota_fmt) {
		char *fmtname = "";

		switch (NBFS_OPTION(sbi).s_jquota_fmt) {
		case QFMT_VFS_OLD:
			fmtname = "vfsold";
			break;
		case QFMT_VFS_V0:
			fmtname = "vfsv0";
			break;
		case QFMT_VFS_V1:
			fmtname = "vfsv1";
			break;
		}
		seq_printf(seq, ",jqfmt=%s", fmtname);
	}

	if (NBFS_OPTION(sbi).s_qf_names[USRQUOTA])
		seq_show_option(seq, "usrjquota",
			NBFS_OPTION(sbi).s_qf_names[USRQUOTA]);

	if (NBFS_OPTION(sbi).s_qf_names[GRPQUOTA])
		seq_show_option(seq, "grpjquota",
			NBFS_OPTION(sbi).s_qf_names[GRPQUOTA]);

	if (NBFS_OPTION(sbi).s_qf_names[PRJQUOTA])
		seq_show_option(seq, "prjjquota",
			NBFS_OPTION(sbi).s_qf_names[PRJQUOTA]);
#endif
}

static int nbfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct nbfs_sb_info *sbi = NBFS_SB(root->d_sb);

	if (!nbfs_readonly(sbi->sb) && test_opt(sbi, BG_GC)) {
		if (test_opt(sbi, FORCE_FG_GC))
			seq_printf(seq, ",background_gc=%s", "sync");
		else
			seq_printf(seq, ",background_gc=%s", "on");
	} else {
		seq_printf(seq, ",background_gc=%s", "off");
	}
	if (test_opt(sbi, DISABLE_ROLL_FORWARD))
		seq_puts(seq, ",disable_roll_forward");
	if (test_opt(sbi, DISCARD))
		seq_puts(seq, ",discard");
	if (test_opt(sbi, NOHEAP))
		seq_puts(seq, ",no_heap");
	else
		seq_puts(seq, ",heap");
#ifdef CONFIG_NBFS_FS_XATTR
	if (test_opt(sbi, XATTR_USER))
		seq_puts(seq, ",user_xattr");
	else
		seq_puts(seq, ",nouser_xattr");
	if (test_opt(sbi, INLINE_XATTR))
		seq_puts(seq, ",inline_xattr");
	else
		seq_puts(seq, ",noinline_xattr");
	if (test_opt(sbi, INLINE_XATTR_SIZE))
		seq_printf(seq, ",inline_xattr_size=%u",
					NBFS_OPTION(sbi).inline_xattr_size);
#endif
#ifdef CONFIG_NBFS_FS_POSIX_ACL
	if (test_opt(sbi, POSIX_ACL))
		seq_puts(seq, ",acl");
	else
		seq_puts(seq, ",noacl");
#endif
	if (test_opt(sbi, DISABLE_EXT_IDENTIFY))
		seq_puts(seq, ",disable_ext_identify");
	if (test_opt(sbi, INLINE_DATA))
		seq_puts(seq, ",inline_data");
	else
		seq_puts(seq, ",noinline_data");
	if (test_opt(sbi, INLINE_DENTRY))
		seq_puts(seq, ",inline_dentry");
	else
		seq_puts(seq, ",noinline_dentry");
	if (!nbfs_readonly(sbi->sb) && test_opt(sbi, FLUSH_MERGE))
		seq_puts(seq, ",flush_merge");
	if (test_opt(sbi, NOBARRIER))
		seq_puts(seq, ",nobarrier");
	if (test_opt(sbi, FASTBOOT))
		seq_puts(seq, ",fastboot");
	if (test_opt(sbi, EXTENT_CACHE))
		seq_puts(seq, ",extent_cache");
	else
		seq_puts(seq, ",noextent_cache");
	if (test_opt(sbi, DATA_FLUSH))
		seq_puts(seq, ",data_flush");

	seq_puts(seq, ",mode=");
	if (test_opt(sbi, ADAPTIVE))
		seq_puts(seq, "adaptive");
	else if (test_opt(sbi, LFS))
		seq_puts(seq, "lfs");
	seq_printf(seq, ",active_logs=%u", NBFS_OPTION(sbi).active_logs);
	if (test_opt(sbi, RESERVE_ROOT))
		seq_printf(seq, ",reserve_root=%u,resuid=%u,resgid=%u",
				NBFS_OPTION(sbi).root_reserved_blocks,
				from_kuid_munged(&init_user_ns,
					NBFS_OPTION(sbi).s_resuid),
				from_kgid_munged(&init_user_ns,
					NBFS_OPTION(sbi).s_resgid));
	if (NBFS_IO_SIZE_BITS(sbi))
		seq_printf(seq, ",io_bits=%u",
				NBFS_OPTION(sbi).write_io_size_bits);
#ifdef CONFIG_NBFS_FAULT_INJECTION
	if (test_opt(sbi, FAULT_INJECTION)) {
		seq_printf(seq, ",fault_injection=%u",
				NBFS_OPTION(sbi).fault_info.inject_rate);
		seq_printf(seq, ",fault_type=%u",
				NBFS_OPTION(sbi).fault_info.inject_type);
	}
#endif
#ifdef CONFIG_QUOTA
	if (test_opt(sbi, QUOTA))
		seq_puts(seq, ",quota");
	if (test_opt(sbi, USRQUOTA))
		seq_puts(seq, ",usrquota");
	if (test_opt(sbi, GRPQUOTA))
		seq_puts(seq, ",grpquota");
	if (test_opt(sbi, PRJQUOTA))
		seq_puts(seq, ",prjquota");
#endif
	nbfs_show_quota_options(seq, sbi->sb);
	if (NBFS_OPTION(sbi).whint_mode == WHINT_MODE_USER)
		seq_printf(seq, ",whint_mode=%s", "user-based");
	else if (NBFS_OPTION(sbi).whint_mode == WHINT_MODE_FS)
		seq_printf(seq, ",whint_mode=%s", "fs-based");
#ifdef CONFIG_FS_ENCRYPTION
	if (NBFS_OPTION(sbi).test_dummy_encryption)
		seq_puts(seq, ",test_dummy_encryption");
#endif

	if (NBFS_OPTION(sbi).alloc_mode == ALLOC_MODE_DEFAULT)
		seq_printf(seq, ",alloc_mode=%s", "default");
	else if (NBFS_OPTION(sbi).alloc_mode == ALLOC_MODE_REUSE)
		seq_printf(seq, ",alloc_mode=%s", "reuse");

	if (test_opt(sbi, DISABLE_CHECKPOINT))
		seq_puts(seq, ",checkpoint=disable");

	if (NBFS_OPTION(sbi).fsync_mode == FSYNC_MODE_POSIX)
		seq_printf(seq, ",fsync_mode=%s", "posix");
	else if (NBFS_OPTION(sbi).fsync_mode == FSYNC_MODE_STRICT)
		seq_printf(seq, ",fsync_mode=%s", "strict");
	else if (NBFS_OPTION(sbi).fsync_mode == FSYNC_MODE_NOBARRIER)
		seq_printf(seq, ",fsync_mode=%s", "nobarrier");
	return 0;
}

static void default_options(struct nbfs_sb_info *sbi)
{
	/* init some FS parameters */
	NBFS_OPTION(sbi).active_logs = NR_CURSEG_TYPE;
	NBFS_OPTION(sbi).inline_xattr_size = DEFAULT_INLINE_XATTR_ADDRS;
	NBFS_OPTION(sbi).whint_mode = WHINT_MODE_OFF;
	NBFS_OPTION(sbi).alloc_mode = ALLOC_MODE_DEFAULT;
	NBFS_OPTION(sbi).fsync_mode = FSYNC_MODE_POSIX;
	NBFS_OPTION(sbi).test_dummy_encryption = false;
	NBFS_OPTION(sbi).s_resuid = make_kuid(&init_user_ns, NBFS_DEF_RESUID);
	NBFS_OPTION(sbi).s_resgid = make_kgid(&init_user_ns, NBFS_DEF_RESGID);

	set_opt(sbi, BG_GC);
	set_opt(sbi, INLINE_XATTR);
	set_opt(sbi, INLINE_DATA);
	set_opt(sbi, INLINE_DENTRY);
	set_opt(sbi, EXTENT_CACHE);
	set_opt(sbi, NOHEAP);
	clear_opt(sbi, DISABLE_CHECKPOINT);
	sbi->sb->s_flags |= SB_LAZYTIME;
	set_opt(sbi, FLUSH_MERGE);
	set_opt(sbi, DISCARD);
	if (nbfs_sb_has_blkzoned(sbi))
		set_opt_mode(sbi, NBFS_MOUNT_LFS);
	else
		set_opt_mode(sbi, NBFS_MOUNT_ADAPTIVE);

#ifdef CONFIG_NBFS_FS_XATTR
	set_opt(sbi, XATTR_USER);
#endif
#ifdef CONFIG_NBFS_FS_POSIX_ACL
	set_opt(sbi, POSIX_ACL);
#endif

	nbfs_build_fault_attr(sbi, 0, 0);
}

#ifdef CONFIG_QUOTA
static int nbfs_enable_quotas(struct super_block *sb);
#endif

static int nbfs_disable_checkpoint(struct nbfs_sb_info *sbi)
{
	unsigned int s_flags = sbi->sb->s_flags;
	struct cp_control cpc;
	int err = 0;
	int ret;

	if (s_flags & SB_RDONLY) {
		nbfs_msg(sbi->sb, KERN_ERR,
				"checkpoint=disable on readonly fs");
		return -EINVAL;
	}
	sbi->sb->s_flags |= SB_ACTIVE;

	nbfs_update_time(sbi, DISABLE_TIME);

	while (!nbfs_time_over(sbi, DISABLE_TIME)) {
		mutex_lock(&sbi->gc_mutex);
		err = nbfs_gc(sbi, true, false, NULL_SEGNO);
		if (err == -ENODATA) {
			err = 0;
			break;
		}
		if (err && err != -EAGAIN)
			break;
	}

	ret = sync_filesystem(sbi->sb);
	if (ret || err) {
		err = ret ? ret: err;
		goto restore_flag;
	}

	if (nbfs_disable_cp_again(sbi)) {
		err = -EAGAIN;
		goto restore_flag;
	}

	mutex_lock(&sbi->gc_mutex);
	cpc.reason = CP_PAUSE;
	set_sbi_flag(sbi, SBI_CP_DISABLED);
	nbfs_write_checkpoint(sbi, &cpc);

	sbi->unusable_block_count = 0;
	mutex_unlock(&sbi->gc_mutex);
restore_flag:
	sbi->sb->s_flags = s_flags;	/* Restore MS_RDONLY status */
	return err;
}

static void nbfs_enable_checkpoint(struct nbfs_sb_info *sbi)
{
	mutex_lock(&sbi->gc_mutex);
	nbfs_dirty_to_prefree(sbi);

	clear_sbi_flag(sbi, SBI_CP_DISABLED);
	set_sbi_flag(sbi, SBI_IS_DIRTY);
	mutex_unlock(&sbi->gc_mutex);

	nbfs_sync_fs(sbi->sb, 1);
}

static int nbfs_remount(struct super_block *sb, int *flags, char *data)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	struct nbfs_mount_info org_mount_opt;
	unsigned long old_sb_flags;
	int err;
	bool need_restart_gc = false;
	bool need_stop_gc = false;
	bool no_extent_cache = !test_opt(sbi, EXTENT_CACHE);
	bool disable_checkpoint = test_opt(sbi, DISABLE_CHECKPOINT);
	bool checkpoint_changed;
#ifdef CONFIG_QUOTA
	int i, j;
#endif

	/*
	 * Save the old mount options in case we
	 * need to restore them.
	 */
	org_mount_opt = sbi->mount_opt;
	old_sb_flags = sb->s_flags;

#ifdef CONFIG_QUOTA
	org_mount_opt.s_jquota_fmt = NBFS_OPTION(sbi).s_jquota_fmt;
	for (i = 0; i < MAXQUOTAS; i++) {
		if (NBFS_OPTION(sbi).s_qf_names[i]) {
			org_mount_opt.s_qf_names[i] =
				kstrdup(NBFS_OPTION(sbi).s_qf_names[i],
				GFP_KERNEL);
			if (!org_mount_opt.s_qf_names[i]) {
				for (j = 0; j < i; j++)
					kvfree(org_mount_opt.s_qf_names[j]);
				return -ENOMEM;
			}
		} else {
			org_mount_opt.s_qf_names[i] = NULL;
		}
	}
#endif

	/* recover superblocks we couldn't write due to previous RO mount */
	if (!(*flags & SB_RDONLY) && is_sbi_flag_set(sbi, SBI_NEED_SB_WRITE)) {
		err = nbfs_commit_super(sbi, false);
		nbfs_msg(sb, KERN_INFO,
			"Try to recover all the superblocks, ret: %d", err);
		if (!err)
			clear_sbi_flag(sbi, SBI_NEED_SB_WRITE);
	}

	default_options(sbi);

	/* parse mount options */
	err = parse_options(sb, data);
	if (err)
		goto restore_opts;
	checkpoint_changed =
			disable_checkpoint != test_opt(sbi, DISABLE_CHECKPOINT);

	/*
	 * Previous and new state of filesystem is RO,
	 * so skip checking GC and FLUSH_MERGE conditions.
	 */
	if (nbfs_readonly(sb) && (*flags & SB_RDONLY))
		goto skip;

#ifdef CONFIG_QUOTA
	if (!nbfs_readonly(sb) && (*flags & SB_RDONLY)) {
		err = dquot_suspend(sb, -1);
		if (err < 0)
			goto restore_opts;
	} else if (nbfs_readonly(sb) && !(*flags & SB_RDONLY)) {
		/* dquot_resume needs RW */
		sb->s_flags &= ~SB_RDONLY;
		if (sb_any_quota_suspended(sb)) {
			dquot_resume(sb, -1);
		} else if (nbfs_sb_has_quota_ino(sbi)) {
			err = nbfs_enable_quotas(sb);
			if (err)
				goto restore_opts;
		}
	}
#endif
	/* disallow enable/disable extent_cache dynamically */
	if (no_extent_cache == !!test_opt(sbi, EXTENT_CACHE)) {
		err = -EINVAL;
		nbfs_msg(sbi->sb, KERN_WARNING,
				"switch extent_cache option is not allowed");
		goto restore_opts;
	}

	if ((*flags & SB_RDONLY) && test_opt(sbi, DISABLE_CHECKPOINT)) {
		err = -EINVAL;
		nbfs_msg(sbi->sb, KERN_WARNING,
			"disabling checkpoint not compatible with read-only");
		goto restore_opts;
	}

	/*
	 * We stop the GC thread if FS is mounted as RO
	 * or if background_gc = off is passed in mount
	 * option. Also sync the filesystem.
	 */
	if ((*flags & SB_RDONLY) || !test_opt(sbi, BG_GC)) {
		if (sbi->gc_thread) {
			nbfs_stop_gc_thread(sbi);
			need_restart_gc = true;
		}
	} else if (!sbi->gc_thread) {
		err = nbfs_start_gc_thread(sbi);
		if (err)
			goto restore_opts;
		need_stop_gc = true;
	}

	if (*flags & SB_RDONLY ||
		NBFS_OPTION(sbi).whint_mode != org_mount_opt.whint_mode) {
		writeback_inodes_sb(sb, WB_REASON_SYNC);
		sync_inodes_sb(sb);

		set_sbi_flag(sbi, SBI_IS_DIRTY);
		set_sbi_flag(sbi, SBI_IS_CLOSE);
		nbfs_sync_fs(sb, 1);
		clear_sbi_flag(sbi, SBI_IS_CLOSE);
	}

	if (checkpoint_changed) {
		if (test_opt(sbi, DISABLE_CHECKPOINT)) {
			err = nbfs_disable_checkpoint(sbi);
			if (err)
				goto restore_gc;
		} else {
			nbfs_enable_checkpoint(sbi);
		}
	}

	/*
	 * We stop issue flush thread if FS is mounted as RO
	 * or if flush_merge is not passed in mount option.
	 */
	if ((*flags & SB_RDONLY) || !test_opt(sbi, FLUSH_MERGE)) {
		clear_opt(sbi, FLUSH_MERGE);
		nbfs_destroy_flush_cmd_control(sbi, false);
	} else {
		err = nbfs_create_flush_cmd_control(sbi);
		if (err)
			goto restore_gc;
	}
skip:
#ifdef CONFIG_QUOTA
	/* Release old quota file names */
	for (i = 0; i < MAXQUOTAS; i++)
		kvfree(org_mount_opt.s_qf_names[i]);
#endif
	/* Update the POSIXACL Flag */
	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
		(test_opt(sbi, POSIX_ACL) ? SB_POSIXACL : 0);

	limit_reserve_root(sbi);
	*flags = (*flags & ~SB_LAZYTIME) | (sb->s_flags & SB_LAZYTIME);
	return 0;
restore_gc:
	if (need_restart_gc) {
		if (nbfs_start_gc_thread(sbi))
			nbfs_msg(sbi->sb, KERN_WARNING,
				"background gc thread has stopped");
	} else if (need_stop_gc) {
		nbfs_stop_gc_thread(sbi);
	}
restore_opts:
#ifdef CONFIG_QUOTA
	NBFS_OPTION(sbi).s_jquota_fmt = org_mount_opt.s_jquota_fmt;
	for (i = 0; i < MAXQUOTAS; i++) {
		kvfree(NBFS_OPTION(sbi).s_qf_names[i]);
		NBFS_OPTION(sbi).s_qf_names[i] = org_mount_opt.s_qf_names[i];
	}
#endif
	sbi->mount_opt = org_mount_opt;
	sb->s_flags = old_sb_flags;
	return err;
}

#ifdef CONFIG_QUOTA
/* Read data from quotafile */
static ssize_t nbfs_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	struct address_space *mapping = inode->i_mapping;
	block_t blkidx = NBFS_BYTES_TO_BLK(off);
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t toread;
	loff_t i_size = i_size_read(inode);
	struct page *page;
	char *kaddr;

	if (off > i_size)
		return 0;

	if (off + len > i_size)
		len = i_size - off;
	toread = len;
	while (toread > 0) {
		tocopy = min_t(unsigned long, sb->s_blocksize - offset, toread);
repeat:
		page = read_cache_page_gfp(mapping, blkidx, GFP_NOFS);
		if (IS_ERR(page)) {
			if (PTR_ERR(page) == -ENOMEM) {
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto repeat;
			}
			set_sbi_flag(NBFS_SB(sb), SBI_QUOTA_NEED_REPAIR);
			return PTR_ERR(page);
		}

		lock_page(page);

		if (unlikely(page->mapping != mapping)) {
			nbfs_put_page(page, 1);
			goto repeat;
		}
		if (unlikely(!PageUptodate(page))) {
			nbfs_put_page(page, 1);
			set_sbi_flag(NBFS_SB(sb), SBI_QUOTA_NEED_REPAIR);
			return -EIO;
		}

		kaddr = kmap_atomic(page);
		memcpy(data, kaddr + offset, tocopy);
		kunmap_atomic(kaddr);
		nbfs_put_page(page, 1);

		offset = 0;
		toread -= tocopy;
		data += tocopy;
		blkidx++;
	}
	return len;
}

/* Write to quotafile */
static ssize_t nbfs_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	struct address_space *mapping = inode->i_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	int offset = off & (sb->s_blocksize - 1);
	size_t towrite = len;
	struct page *page;
	char *kaddr;
	int err = 0;
	int tocopy;

	while (towrite > 0) {
		tocopy = min_t(unsigned long, sb->s_blocksize - offset,
								towrite);
retry:
		err = a_ops->write_begin(NULL, mapping, off, tocopy, 0,
							&page, NULL);
		if (unlikely(err)) {
			if (err == -ENOMEM) {
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto retry;
			}
			set_sbi_flag(NBFS_SB(sb), SBI_QUOTA_NEED_REPAIR);
			break;
		}

		kaddr = kmap_atomic(page);
		memcpy(kaddr + offset, data, tocopy);
		kunmap_atomic(kaddr);
		flush_dcache_page(page);

		a_ops->write_end(NULL, mapping, off, tocopy, tocopy,
						page, NULL);
		offset = 0;
		towrite -= tocopy;
		off += tocopy;
		data += tocopy;
		cond_resched();
	}

	if (len == towrite)
		return err;
	inode->i_mtime = inode->i_ctime = current_time(inode);
	nbfs_mark_inode_dirty_sync(inode, false);
	return len - towrite;
}

static struct dquot **nbfs_get_dquots(struct inode *inode)
{
	return NBFS_I(inode)->i_dquot;
}

static qsize_t *nbfs_get_reserved_space(struct inode *inode)
{
	return &NBFS_I(inode)->i_reserved_quota;
}

static int nbfs_quota_on_mount(struct nbfs_sb_info *sbi, int type)
{
	if (is_set_ckpt_flags(sbi, CP_QUOTA_NEED_FSCK_FLAG)) {
		nbfs_msg(sbi->sb, KERN_ERR,
			"quota sysfile may be corrupted, skip loading it");
		return 0;
	}

	return dquot_quota_on_mount(sbi->sb, NBFS_OPTION(sbi).s_qf_names[type],
					NBFS_OPTION(sbi).s_jquota_fmt, type);
}

int nbfs_enable_quota_files(struct nbfs_sb_info *sbi, bool rdonly)
{
	int enabled = 0;
	int i, err;

	if (nbfs_sb_has_quota_ino(sbi) && rdonly) {
		err = nbfs_enable_quotas(sbi->sb);
		if (err) {
			nbfs_msg(sbi->sb, KERN_ERR,
					"Cannot turn on quota_ino: %d", err);
			return 0;
		}
		return 1;
	}

	for (i = 0; i < MAXQUOTAS; i++) {
		if (NBFS_OPTION(sbi).s_qf_names[i]) {
			err = nbfs_quota_on_mount(sbi, i);
			if (!err) {
				enabled = 1;
				continue;
			}
			nbfs_msg(sbi->sb, KERN_ERR,
				"Cannot turn on quotas: %d on %d", err, i);
		}
	}
	return enabled;
}

static int nbfs_quota_enable(struct super_block *sb, int type, int format_id,
			     unsigned int flags)
{
	struct inode *qf_inode;
	unsigned long qf_inum;
	int err;

	BUG_ON(!nbfs_sb_has_quota_ino(NBFS_SB(sb)));

	qf_inum = nbfs_qf_ino(sb, type);
	if (!qf_inum)
		return -EPERM;

	qf_inode = nbfs_iget(sb, qf_inum);
	if (IS_ERR(qf_inode)) {
		nbfs_msg(sb, KERN_ERR,
			"Bad quota inode %u:%lu", type, qf_inum);
		return PTR_ERR(qf_inode);
	}

	/* Don't account quota for quota files to avoid recursion */
	qf_inode->i_flags |= S_NOQUOTA;
	err = dquot_enable(qf_inode, type, format_id, flags);
	iput(qf_inode);
	return err;
}

static int nbfs_enable_quotas(struct super_block *sb)
{
	int type, err = 0;
	unsigned long qf_inum;
	bool quota_mopt[MAXQUOTAS] = {
		test_opt(NBFS_SB(sb), USRQUOTA),
		test_opt(NBFS_SB(sb), GRPQUOTA),
		test_opt(NBFS_SB(sb), PRJQUOTA),
	};

	if (is_set_ckpt_flags(NBFS_SB(sb), CP_QUOTA_NEED_FSCK_FLAG)) {
		nbfs_msg(sb, KERN_ERR,
			"quota file may be corrupted, skip loading it");
		return 0;
	}

	sb_dqopt(sb)->flags |= DQUOT_QUOTA_SYS_FILE;

	for (type = 0; type < MAXQUOTAS; type++) {
		qf_inum = nbfs_qf_ino(sb, type);
		if (qf_inum) {
			err = nbfs_quota_enable(sb, type, QFMT_VFS_V1,
				DQUOT_USAGE_ENABLED |
				(quota_mopt[type] ? DQUOT_LIMITS_ENABLED : 0));
			if (err) {
				nbfs_msg(sb, KERN_ERR,
					"Failed to enable quota tracking "
					"(type=%d, err=%d). Please run "
					"fsck to fix.", type, err);
				for (type--; type >= 0; type--)
					dquot_quota_off(sb, type);
				set_sbi_flag(NBFS_SB(sb),
						SBI_QUOTA_NEED_REPAIR);
				return err;
			}
		}
	}
	return 0;
}

int nbfs_quota_sync(struct super_block *sb, int type)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	struct quota_info *dqopt = sb_dqopt(sb);
	int cnt;
	int ret;

	ret = dquot_writeback_dquots(sb, type);
	if (ret)
		goto out;

	/*
	 * Now when everything is written we can discard the pagecache so
	 * that userspace sees the changes.
	 */
	for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
		struct address_space *mapping;

		if (type != -1 && cnt != type)
			continue;
		if (!sb_has_quota_active(sb, cnt))
			continue;

		mapping = dqopt->files[cnt]->i_mapping;

		ret = filemap_fdatawrite(mapping);
		if (ret)
			goto out;

		/* if we are using journalled quota */
		if (is_journalled_quota(sbi))
			continue;

		ret = filemap_fdatawait(mapping);
		if (ret)
			set_sbi_flag(NBFS_SB(sb), SBI_QUOTA_NEED_REPAIR);

		inode_lock(dqopt->files[cnt]);
		truncate_inode_pages(&dqopt->files[cnt]->i_data, 0);
		inode_unlock(dqopt->files[cnt]);
	}
out:
	if (ret)
		set_sbi_flag(NBFS_SB(sb), SBI_QUOTA_NEED_REPAIR);
	return ret;
}

static int nbfs_quota_on(struct super_block *sb, int type, int format_id,
							const struct path *path)
{
	struct inode *inode;
	int err;

	err = nbfs_quota_sync(sb, type);
	if (err)
		return err;

	err = dquot_quota_on(sb, type, format_id, path);
	if (err)
		return err;

	inode = d_inode(path->dentry);

	inode_lock(inode);
	NBFS_I(inode)->i_flags |= NBFS_NOATIME_FL | NBFS_IMMUTABLE_FL;
	nbfs_set_inode_flags(inode);
	inode_unlock(inode);
	nbfs_mark_inode_dirty_sync(inode, false);

	return 0;
}

static int nbfs_quota_off(struct super_block *sb, int type)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	int err;

	if (!inode || !igrab(inode))
		return dquot_quota_off(sb, type);

	err = nbfs_quota_sync(sb, type);
	if (err)
		goto out_put;

	err = dquot_quota_off(sb, type);
	if (err || nbfs_sb_has_quota_ino(NBFS_SB(sb)))
		goto out_put;

	inode_lock(inode);
	NBFS_I(inode)->i_flags &= ~(NBFS_NOATIME_FL | NBFS_IMMUTABLE_FL);
	nbfs_set_inode_flags(inode);
	inode_unlock(inode);
	nbfs_mark_inode_dirty_sync(inode, false);
out_put:
	iput(inode);
	return err;
}

void nbfs_quota_off_umount(struct super_block *sb)
{
	int type;
	int err;

	for (type = 0; type < MAXQUOTAS; type++) {
		err = nbfs_quota_off(sb, type);
		if (err) {
			int ret = dquot_quota_off(sb, type);

			nbfs_msg(sb, KERN_ERR,
				"Fail to turn off disk quota "
				"(type: %d, err: %d, ret:%d), Please "
				"run fsck to fix it.", type, err, ret);
			set_sbi_flag(NBFS_SB(sb), SBI_QUOTA_NEED_REPAIR);
		}
	}
	/*
	 * In case of checkpoint=disable, we must flush quota blocks.
	 * This can cause NULL exception for node_inode in end_io, since
	 * put_super already dropped it.
	 */
	sync_filesystem(sb);
}

static void nbfs_truncate_quota_inode_pages(struct super_block *sb)
{
	struct quota_info *dqopt = sb_dqopt(sb);
	int type;

	for (type = 0; type < MAXQUOTAS; type++) {
		if (!dqopt->files[type])
			continue;
		nbfs_inode_synced(dqopt->files[type]);
	}
}

static int nbfs_dquot_commit(struct dquot *dquot)
{
	int ret;

	ret = dquot_commit(dquot);
	if (ret < 0)
		set_sbi_flag(NBFS_SB(dquot->dq_sb), SBI_QUOTA_NEED_REPAIR);
	return ret;
}

static int nbfs_dquot_acquire(struct dquot *dquot)
{
	int ret;

	ret = dquot_acquire(dquot);
	if (ret < 0)
		set_sbi_flag(NBFS_SB(dquot->dq_sb), SBI_QUOTA_NEED_REPAIR);

	return ret;
}

static int nbfs_dquot_release(struct dquot *dquot)
{
	int ret;

	ret = dquot_release(dquot);
	if (ret < 0)
		set_sbi_flag(NBFS_SB(dquot->dq_sb), SBI_QUOTA_NEED_REPAIR);
	return ret;
}

static int nbfs_dquot_mark_dquot_dirty(struct dquot *dquot)
{
	struct super_block *sb = dquot->dq_sb;
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	int ret;

	ret = dquot_mark_dquot_dirty(dquot);

	/* if we are using journalled quota */
	if (is_journalled_quota(sbi))
		set_sbi_flag(sbi, SBI_QUOTA_NEED_FLUSH);

	return ret;
}

static int nbfs_dquot_commit_info(struct super_block *sb, int type)
{
	int ret;

	ret = dquot_commit_info(sb, type);
	if (ret < 0)
		set_sbi_flag(NBFS_SB(sb), SBI_QUOTA_NEED_REPAIR);
	return ret;
}

static int nbfs_get_projid(struct inode *inode, kprojid_t *projid)
{
	*projid = NBFS_I(inode)->i_projid;
	return 0;
}

static const struct dquot_operations nbfs_quota_operations = {
	.get_reserved_space = nbfs_get_reserved_space,
	.write_dquot	= nbfs_dquot_commit,
	.acquire_dquot	= nbfs_dquot_acquire,
	.release_dquot	= nbfs_dquot_release,
	.mark_dirty	= nbfs_dquot_mark_dquot_dirty,
	.write_info	= nbfs_dquot_commit_info,
	.alloc_dquot	= dquot_alloc,
	.destroy_dquot	= dquot_destroy,
	.get_projid	= nbfs_get_projid,
	.get_next_id	= dquot_get_next_id,
};

static const struct quotactl_ops nbfs_quotactl_ops = {
	.quota_on	= nbfs_quota_on,
	.quota_off	= nbfs_quota_off,
	.quota_sync	= nbfs_quota_sync,
	.get_state	= dquot_get_state,
	.set_info	= dquot_set_dqinfo,
	.get_dqblk	= dquot_get_dqblk,
	.set_dqblk	= dquot_set_dqblk,
	.get_nextdqblk	= dquot_get_next_dqblk,
};
#else
int nbfs_quota_sync(struct super_block *sb, int type)
{
	return 0;
}

void nbfs_quota_off_umount(struct super_block *sb)
{
}
#endif

static const struct super_operations nbfs_sops = {
	.alloc_inode	= nbfs_alloc_inode,
	.drop_inode	= nbfs_drop_inode,
	.destroy_inode	= nbfs_destroy_inode,
	.write_inode	= nbfs_write_inode,
	.dirty_inode	= nbfs_dirty_inode,
	.show_options	= nbfs_show_options,
#ifdef CONFIG_QUOTA
	.quota_read	= nbfs_quota_read,
	.quota_write	= nbfs_quota_write,
	.get_dquots	= nbfs_get_dquots,
#endif
	.evict_inode	= nbfs_evict_inode,
	.put_super	= nbfs_put_super,
	.sync_fs	= nbfs_sync_fs,
	.freeze_fs	= nbfs_freeze,
	.unfreeze_fs	= nbfs_unfreeze,
	.statfs		= nbfs_statfs,
	.remount_fs	= nbfs_remount,
};

#ifdef CONFIG_FS_ENCRYPTION
static int nbfs_get_context(struct inode *inode, void *ctx, size_t len)
{
	return nbfs_getxattr(inode, NBFS_XATTR_INDEX_ENCRYPTION,
				NBFS_XATTR_NAME_ENCRYPTION_CONTEXT,
				ctx, len, NULL);
}

static int nbfs_set_context(struct inode *inode, const void *ctx, size_t len,
							void *fs_data)
{
	struct nbfs_sb_info *sbi = NBFS_I_SB(inode);

	/*
	 * Encrypting the root directory is not allowed because fsck
	 * expects lost+found directory to exist and remain unencrypted
	 * if LOST_FOUND feature is enabled.
	 *
	 */
	if (nbfs_sb_has_lost_found(sbi) &&
			inode->i_ino == NBFS_ROOT_INO(sbi))
		return -EPERM;

	return nbfs_setxattr(inode, NBFS_XATTR_INDEX_ENCRYPTION,
				NBFS_XATTR_NAME_ENCRYPTION_CONTEXT,
				ctx, len, fs_data, XATTR_CREATE);
}

static bool nbfs_dummy_context(struct inode *inode)
{
	return DUMMY_ENCRYPTION_ENABLED(NBFS_I_SB(inode));
}

static const struct fscrypt_operations nbfs_cryptops = {
	.key_prefix	= "nbfs:",
	.get_context	= nbfs_get_context,
	.set_context	= nbfs_set_context,
	.dummy_context	= nbfs_dummy_context,
	.empty_dir	= nbfs_empty_dir,
	.max_namelen	= NBFS_NAME_LEN,
};
#endif

static struct inode *nbfs_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	struct inode *inode;

	if (nbfs_check_nid_range(sbi, ino))
		return ERR_PTR(-ESTALE);

	/*
	 * nbfs_iget isn't quite right if the inode is currently unallocated!
	 * However nbfs_iget currently does appropriate checks to handle stale
	 * inodes so everything is OK.
	 */
	inode = nbfs_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (unlikely(generation && inode->i_generation != generation)) {
		/* we didn't find the right inode.. */
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return inode;
}

static struct dentry *nbfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    nbfs_nfs_get_inode);
}

static struct dentry *nbfs_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    nbfs_nfs_get_inode);
}

static const struct export_operations nbfs_export_ops = {
	.fh_to_dentry = nbfs_fh_to_dentry,
	.fh_to_parent = nbfs_fh_to_parent,
	.get_parent = nbfs_get_parent,
};

static loff_t max_file_blocks(void)
{
	loff_t result = 0;
	loff_t leaf_count = ADDRS_PER_BLOCK;

	/*
	 * note: previously, result is equal to (DEF_ADDRS_PER_INODE -
	 * DEFAULT_INLINE_XATTR_ADDRS), but now nbfs try to reserve more
	 * space in inode.i_addr, it will be more safe to reassign
	 * result as zero.
	 */

	/* two direct node blocks */
	result += (leaf_count * 2);

	/* two indirect node blocks */
	leaf_count *= NIDS_PER_BLOCK;
	result += (leaf_count * 2);

	/* one double indirect node block */
	leaf_count *= NIDS_PER_BLOCK;
	result += leaf_count;

	return result;
}

static int __nbfs_commit_super(struct buffer_head *bh,
			struct nbfs_super_block *super)
{
	lock_buffer(bh);
	if (super)
		memcpy(bh->b_data + NBFS_SUPER_OFFSET, super, sizeof(*super));
	set_buffer_dirty(bh);
	unlock_buffer(bh);

	/* it's rare case, we can do fua all the time */
	return __sync_dirty_buffer(bh, REQ_SYNC | REQ_PREFLUSH | REQ_FUA);
}

static inline bool sanity_check_area_boundary(struct nbfs_sb_info *sbi,
					struct buffer_head *bh)
{
	struct nbfs_super_block *raw_super = (struct nbfs_super_block *)
					(bh->b_data + NBFS_SUPER_OFFSET);
	struct super_block *sb = sbi->sb;
	u32 segment0_blkaddr = le32_to_cpu(raw_super->segment0_blkaddr);
	u32 cp_blkaddr = le32_to_cpu(raw_super->cp_blkaddr);
	u32 sit_blkaddr = le32_to_cpu(raw_super->sit_blkaddr);
	u32 nat_blkaddr = le32_to_cpu(raw_super->nat_blkaddr);
	u32 ssa_blkaddr = le32_to_cpu(raw_super->ssa_blkaddr);
	u32 main_blkaddr = le32_to_cpu(raw_super->main_blkaddr);
	u32 segment_count_ckpt = le32_to_cpu(raw_super->segment_count_ckpt);
	u32 segment_count_sit = le32_to_cpu(raw_super->segment_count_sit);
	u32 segment_count_nat = le32_to_cpu(raw_super->segment_count_nat);
	u32 segment_count_ssa = le32_to_cpu(raw_super->segment_count_ssa);
	u32 segment_count_main = le32_to_cpu(raw_super->segment_count_main);
	u32 segment_count = le32_to_cpu(raw_super->segment_count);
	u32 log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);
	u64 main_end_blkaddr = main_blkaddr +
				(segment_count_main << log_blocks_per_seg);
	u64 seg_end_blkaddr = segment0_blkaddr +
				(segment_count << log_blocks_per_seg);

	if (segment0_blkaddr != cp_blkaddr) {
		nbfs_msg(sb, KERN_INFO,
			"Mismatch start address, segment0(%u) cp_blkaddr(%u)",
			segment0_blkaddr, cp_blkaddr);
		return true;
	}

	if (cp_blkaddr + (segment_count_ckpt << log_blocks_per_seg) !=
							sit_blkaddr) {
		nbfs_msg(sb, KERN_INFO,
			"Wrong CP boundary, start(%u) end(%u) blocks(%u)",
			cp_blkaddr, sit_blkaddr,
			segment_count_ckpt << log_blocks_per_seg);
		return true;
	}

	if (sit_blkaddr + (segment_count_sit << log_blocks_per_seg) !=
							nat_blkaddr) {
		nbfs_msg(sb, KERN_INFO,
			"Wrong SIT boundary, start(%u) end(%u) blocks(%u)",
			sit_blkaddr, nat_blkaddr,
			segment_count_sit << log_blocks_per_seg);
		return true;
	}

	if (nat_blkaddr + (segment_count_nat << log_blocks_per_seg) !=
							ssa_blkaddr) {
		nbfs_msg(sb, KERN_INFO,
			"Wrong NAT boundary, start(%u) end(%u) blocks(%u)",
			nat_blkaddr, ssa_blkaddr,
			segment_count_nat << log_blocks_per_seg);
		return true;
	}

	if (ssa_blkaddr + (segment_count_ssa << log_blocks_per_seg) !=
							main_blkaddr) {
		nbfs_msg(sb, KERN_INFO,
			"Wrong SSA boundary, start(%u) end(%u) blocks(%u)",
			ssa_blkaddr, main_blkaddr,
			segment_count_ssa << log_blocks_per_seg);
		return true;
	}

	if (main_end_blkaddr > seg_end_blkaddr) {
		nbfs_msg(sb, KERN_INFO,
			"Wrong MAIN_AREA boundary, start(%u) end(%u) block(%u)",
			main_blkaddr,
			segment0_blkaddr +
				(segment_count << log_blocks_per_seg),
			segment_count_main << log_blocks_per_seg);
		return true;
	} else if (main_end_blkaddr < seg_end_blkaddr) {
		int err = 0;
		char *res;

		/* fix in-memory information all the time */
		raw_super->segment_count = cpu_to_le32((main_end_blkaddr -
				segment0_blkaddr) >> log_blocks_per_seg);

		if (nbfs_readonly(sb) || bdev_read_only(sb->s_bdev)) {
			set_sbi_flag(sbi, SBI_NEED_SB_WRITE);
			res = "internally";
		} else {
			err = __nbfs_commit_super(bh, NULL);
			res = err ? "failed" : "done";
		}
		nbfs_msg(sb, KERN_INFO,
			"Fix alignment : %s, start(%u) end(%u) block(%u)",
			res, main_blkaddr,
			segment0_blkaddr +
				(segment_count << log_blocks_per_seg),
			segment_count_main << log_blocks_per_seg);
		if (err)
			return true;
	}

	return false;
}

static int sanity_check_raw_super(struct nbfs_sb_info *sbi,
				struct buffer_head *bh)
{
	block_t segment_count, segs_per_sec, secs_per_zone;
	block_t total_sections, blocks_per_seg;
	struct nbfs_super_block *raw_super = (struct nbfs_super_block *)
					(bh->b_data + NBFS_SUPER_OFFSET);
	struct super_block *sb = sbi->sb;
	unsigned int blocksize;
	size_t crc_offset = 0;
	__u32 crc = 0;

	/* Check checksum_offset and crc in superblock */
	if (__NBFS_HAS_FEATURE(raw_super, NBFS_FEATURE_SB_CHKSUM)) {
		crc_offset = le32_to_cpu(raw_super->checksum_offset);
		if (crc_offset !=
			offsetof(struct nbfs_super_block, crc)) {
			nbfs_msg(sb, KERN_INFO,
				"Invalid SB checksum offset: %zu",
				crc_offset);
			return 1;
		}
		crc = le32_to_cpu(raw_super->crc);
		if (!nbfs_crc_valid(sbi, crc, raw_super, crc_offset)) {
			nbfs_msg(sb, KERN_INFO,
				"Invalid SB checksum value: %u", crc);
			return 1;
		}
	}

	if (F2FS_SUPER_MAGIC != le32_to_cpu(raw_super->magic)) {
		nbfs_msg(sb, KERN_INFO,
			"Magic Mismatch, valid(0x%x) - read(0x%x)",
			F2FS_SUPER_MAGIC, le32_to_cpu(raw_super->magic));
		return 1;
	}

	/* Currently, support only 4KB page cache size */
	if (NBFS_BLKSIZE != PAGE_SIZE) {
		nbfs_msg(sb, KERN_INFO,
			"Invalid page_cache_size (%lu), supports only 4KB\n",
			PAGE_SIZE);
		return 1;
	}

	/* Currently, support only 4KB block size */
	blocksize = 1 << le32_to_cpu(raw_super->log_blocksize);
	if (blocksize != NBFS_BLKSIZE) {
		nbfs_msg(sb, KERN_INFO,
			"Invalid blocksize (%u), supports only 4KB\n",
			blocksize);
		return 1;
	}

	/* check log blocks per segment */
	if (le32_to_cpu(raw_super->log_blocks_per_seg) != 9) {
		nbfs_msg(sb, KERN_INFO,
			"Invalid log blocks per segment (%u)\n",
			le32_to_cpu(raw_super->log_blocks_per_seg));
		return 1;
	}

	/* Currently, support 512/1024/2048/4096 bytes sector size */
	if (le32_to_cpu(raw_super->log_sectorsize) >
				NBFS_MAX_LOG_SECTOR_SIZE ||
		le32_to_cpu(raw_super->log_sectorsize) <
				NBFS_MIN_LOG_SECTOR_SIZE) {
		nbfs_msg(sb, KERN_INFO, "Invalid log sectorsize (%u)",
			le32_to_cpu(raw_super->log_sectorsize));
		return 1;
	}
	if (le32_to_cpu(raw_super->log_sectors_per_block) +
		le32_to_cpu(raw_super->log_sectorsize) !=
			NBFS_MAX_LOG_SECTOR_SIZE) {
		nbfs_msg(sb, KERN_INFO,
			"Invalid log sectors per block(%u) log sectorsize(%u)",
			le32_to_cpu(raw_super->log_sectors_per_block),
			le32_to_cpu(raw_super->log_sectorsize));
		return 1;
	}

	segment_count = le32_to_cpu(raw_super->segment_count);
	segs_per_sec = le32_to_cpu(raw_super->segs_per_sec);
	secs_per_zone = le32_to_cpu(raw_super->secs_per_zone);
	total_sections = le32_to_cpu(raw_super->section_count);

	/* blocks_per_seg should be 512, given the above check */
	blocks_per_seg = 1 << le32_to_cpu(raw_super->log_blocks_per_seg);

	if (segment_count > NBFS_MAX_SEGMENT ||
				segment_count < NBFS_MIN_SEGMENTS) {
		nbfs_msg(sb, KERN_INFO,
			"Invalid segment count (%u)",
			segment_count);
		return 1;
	}

	if (total_sections > segment_count ||
			total_sections < NBFS_MIN_SEGMENTS ||
			segs_per_sec > segment_count || !segs_per_sec) {
		nbfs_msg(sb, KERN_INFO,
			"Invalid segment/section count (%u, %u x %u)",
			segment_count, total_sections, segs_per_sec);
		return 1;
	}

	if ((segment_count / segs_per_sec) < total_sections) {
		nbfs_msg(sb, KERN_INFO,
			"Small segment_count (%u < %u * %u)",
			segment_count, segs_per_sec, total_sections);
		return 1;
	}

	if (segment_count > (le64_to_cpu(raw_super->block_count) >> 9)) {
		nbfs_msg(sb, KERN_INFO,
			"Wrong segment_count / block_count (%u > %llu)",
			segment_count, le64_to_cpu(raw_super->block_count));
		return 1;
	}

	if (secs_per_zone > total_sections || !secs_per_zone) {
		nbfs_msg(sb, KERN_INFO,
			"Wrong secs_per_zone / total_sections (%u, %u)",
			secs_per_zone, total_sections);
		return 1;
	}
	if (le32_to_cpu(raw_super->extension_count) > NBFS_MAX_EXTENSION ||
			raw_super->hot_ext_count > NBFS_MAX_EXTENSION ||
			(le32_to_cpu(raw_super->extension_count) +
			raw_super->hot_ext_count) > NBFS_MAX_EXTENSION) {
		nbfs_msg(sb, KERN_INFO,
			"Corrupted extension count (%u + %u > %u)",
			le32_to_cpu(raw_super->extension_count),
			raw_super->hot_ext_count,
			NBFS_MAX_EXTENSION);
		return 1;
	}

	if (le32_to_cpu(raw_super->cp_payload) >
				(blocks_per_seg - NBFS_CP_PACKS)) {
		nbfs_msg(sb, KERN_INFO,
			"Insane cp_payload (%u > %u)",
			le32_to_cpu(raw_super->cp_payload),
			blocks_per_seg - NBFS_CP_PACKS);
		return 1;
	}

	/* check reserved ino info */
	if (le32_to_cpu(raw_super->node_ino) != 1 ||
		le32_to_cpu(raw_super->meta_ino) != 2 ||
		le32_to_cpu(raw_super->root_ino) != 3) {
		nbfs_msg(sb, KERN_INFO,
			"Invalid Fs Meta Ino: node(%u) meta(%u) root(%u)",
			le32_to_cpu(raw_super->node_ino),
			le32_to_cpu(raw_super->meta_ino),
			le32_to_cpu(raw_super->root_ino));
		return 1;
	}

	/* check CP/SIT/NAT/SSA/MAIN_AREA area boundary */
	if (sanity_check_area_boundary(sbi, bh))
		return 1;

	return 0;
}

int nbfs_sanity_check_ckpt(struct nbfs_sb_info *sbi)
{
	unsigned int total, fsmeta;
	struct nbfs_super_block *raw_super = NBFS_RAW_SUPER(sbi);
	struct nbfs_checkpoint *ckpt = NBFS_CKPT(sbi);
	unsigned int ovp_segments, reserved_segments;
	unsigned int main_segs, blocks_per_seg;
	unsigned int sit_segs, nat_segs;
	unsigned int sit_bitmap_size, nat_bitmap_size;
	unsigned int log_blocks_per_seg;
	unsigned int segment_count_main;
	unsigned int cp_pack_start_sum, cp_payload;
	block_t user_block_count;
	int i, j;

	total = le32_to_cpu(raw_super->segment_count);
	fsmeta = le32_to_cpu(raw_super->segment_count_ckpt);
	sit_segs = le32_to_cpu(raw_super->segment_count_sit);
	fsmeta += sit_segs;
	nat_segs = le32_to_cpu(raw_super->segment_count_nat);
	fsmeta += nat_segs;
	fsmeta += le32_to_cpu(ckpt->rsvd_segment_count);
	fsmeta += le32_to_cpu(raw_super->segment_count_ssa);

	if (unlikely(fsmeta >= total))
		return 1;

	ovp_segments = le32_to_cpu(ckpt->overprov_segment_count);
	reserved_segments = le32_to_cpu(ckpt->rsvd_segment_count);

	if (unlikely(fsmeta < NBFS_MIN_SEGMENTS ||
			ovp_segments == 0 || reserved_segments == 0)) {
		nbfs_msg(sbi->sb, KERN_ERR,
			"Wrong layout: check mkfs.nbfs version");
		return 1;
	}

	user_block_count = le64_to_cpu(ckpt->user_block_count);
	segment_count_main = le32_to_cpu(raw_super->segment_count_main);
	log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);
	if (!user_block_count || user_block_count >=
			segment_count_main << log_blocks_per_seg) {
		nbfs_msg(sbi->sb, KERN_ERR,
			"Wrong user_block_count: %u", user_block_count);
		return 1;
	}

	main_segs = le32_to_cpu(raw_super->segment_count_main);
	blocks_per_seg = sbi->blocks_per_seg;

	for (i = 0; i < NR_CURSEG_NODE_TYPE; i++) {
		if (le32_to_cpu(ckpt->cur_node_segno[i]) >= main_segs ||
			le16_to_cpu(ckpt->cur_node_blkoff[i]) >= blocks_per_seg)
			return 1;
		for (j = i + 1; j < NR_CURSEG_NODE_TYPE; j++) {
			if (le32_to_cpu(ckpt->cur_node_segno[i]) ==
				le32_to_cpu(ckpt->cur_node_segno[j])) {
				nbfs_msg(sbi->sb, KERN_ERR,
					"Node segment (%u, %u) has the same "
					"segno: %u", i, j,
					le32_to_cpu(ckpt->cur_node_segno[i]));
				return 1;
			}
		}
	}
	for (i = 0; i < NR_CURSEG_DATA_TYPE; i++) {
		if (le32_to_cpu(ckpt->cur_data_segno[i]) >= main_segs ||
			le16_to_cpu(ckpt->cur_data_blkoff[i]) >= blocks_per_seg)
			return 1;
		for (j = i + 1; j < NR_CURSEG_DATA_TYPE; j++) {
			if (le32_to_cpu(ckpt->cur_data_segno[i]) ==
				le32_to_cpu(ckpt->cur_data_segno[j])) {
				nbfs_msg(sbi->sb, KERN_ERR,
					"Data segment (%u, %u) has the same "
					"segno: %u", i, j,
					le32_to_cpu(ckpt->cur_data_segno[i]));
				return 1;
			}
		}
	}
	for (i = 0; i < NR_CURSEG_NODE_TYPE; i++) {
		for (j = i; j < NR_CURSEG_DATA_TYPE; j++) {
			if (le32_to_cpu(ckpt->cur_node_segno[i]) ==
				le32_to_cpu(ckpt->cur_data_segno[j])) {
				nbfs_msg(sbi->sb, KERN_ERR,
					"Data segment (%u) and Data segment (%u)"
					" has the same segno: %u", i, j,
					le32_to_cpu(ckpt->cur_node_segno[i]));
				return 1;
			}
		}
	}

	sit_bitmap_size = le32_to_cpu(ckpt->sit_ver_bitmap_bytesize);
	nat_bitmap_size = le32_to_cpu(ckpt->nat_ver_bitmap_bytesize);

	if (sit_bitmap_size != ((sit_segs / 2) << log_blocks_per_seg) / 8 ||
		nat_bitmap_size != ((nat_segs / 2) << log_blocks_per_seg) / 8) {
		nbfs_msg(sbi->sb, KERN_ERR,
			"Wrong bitmap size: sit: %u, nat:%u",
			sit_bitmap_size, nat_bitmap_size);
		return 1;
	}

	cp_pack_start_sum = __start_sum_addr(sbi);
	cp_payload = __cp_payload(sbi);
	if (cp_pack_start_sum < cp_payload + 1 ||
		cp_pack_start_sum > blocks_per_seg - 1 -
			NR_CURSEG_TYPE) {
		nbfs_msg(sbi->sb, KERN_ERR,
			"Wrong cp_pack_start_sum: %u",
			cp_pack_start_sum);
		return 1;
	}

	if (unlikely(nbfs_cp_error(sbi))) {
		nbfs_msg(sbi->sb, KERN_ERR, "A bug case: need to run fsck");
		return 1;
	}
	return 0;
}

static void init_sb_info(struct nbfs_sb_info *sbi)
{
	struct nbfs_super_block *raw_super = sbi->raw_super;
	int i;

	sbi->log_sectors_per_block =
		le32_to_cpu(raw_super->log_sectors_per_block);
	sbi->log_blocksize = le32_to_cpu(raw_super->log_blocksize);
	sbi->blocksize = 1 << sbi->log_blocksize;
	sbi->log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);
	sbi->blocks_per_seg = 1 << sbi->log_blocks_per_seg;
	sbi->segs_per_sec = le32_to_cpu(raw_super->segs_per_sec);
	sbi->secs_per_zone = le32_to_cpu(raw_super->secs_per_zone);
	sbi->total_sections = le32_to_cpu(raw_super->section_count);
	sbi->total_node_count =
		(le32_to_cpu(raw_super->segment_count_nat) / 2)
			* sbi->blocks_per_seg * NAT_ENTRY_PER_BLOCK;
	sbi->root_ino_num = le32_to_cpu(raw_super->root_ino);
	sbi->node_ino_num = le32_to_cpu(raw_super->node_ino);
	sbi->meta_ino_num = le32_to_cpu(raw_super->meta_ino);
	sbi->cur_victim_sec = NULL_SECNO;
	sbi->next_victim_seg[BG_GC] = NULL_SEGNO;
	sbi->next_victim_seg[FG_GC] = NULL_SEGNO;
	sbi->max_victim_search = DEF_MAX_VICTIM_SEARCH;
	sbi->migration_granularity = sbi->segs_per_sec;

	sbi->dir_level = DEF_DIR_LEVEL;
	sbi->interval_time[CP_TIME] = DEF_CP_INTERVAL;
	sbi->interval_time[REQ_TIME] = DEF_IDLE_INTERVAL;
	sbi->interval_time[DISCARD_TIME] = DEF_IDLE_INTERVAL;
	sbi->interval_time[GC_TIME] = DEF_IDLE_INTERVAL;
	sbi->interval_time[DISABLE_TIME] = DEF_DISABLE_INTERVAL;
	sbi->interval_time[UMOUNT_DISCARD_TIMEOUT] =
				DEF_UMOUNT_DISCARD_TIMEOUT;
	clear_sbi_flag(sbi, SBI_NEED_FSCK);

	for (i = 0; i < NR_COUNT_TYPE; i++)
		atomic_set(&sbi->nr_pages[i], 0);

	for (i = 0; i < META; i++)
		atomic_set(&sbi->wb_sync_req[i], 0);

	INIT_LIST_HEAD(&sbi->s_list);
	mutex_init(&sbi->umount_mutex);
	init_rwsem(&sbi->io_order_lock);
	spin_lock_init(&sbi->cp_lock);

	sbi->dirty_device = 0;
	spin_lock_init(&sbi->dev_lock);

	init_rwsem(&sbi->sb_lock);
}

static int init_percpu_info(struct nbfs_sb_info *sbi)
{
	int err;

	err = percpu_counter_init(&sbi->alloc_valid_block_count, 0, GFP_KERNEL);
	if (err)
		return err;

	err = percpu_counter_init(&sbi->total_valid_inode_count, 0,
								GFP_KERNEL);
	if (err)
		percpu_counter_destroy(&sbi->alloc_valid_block_count);

	return err;
}

#ifdef CONFIG_BLK_DEV_ZONED
static int init_blkz_info(struct nbfs_sb_info *sbi, int devi)
{
	struct block_device *bdev = FDEV(devi).bdev;
	sector_t nr_sectors = bdev->bd_part->nr_sects;
	sector_t sector = 0;
	struct blk_zone *zones;
	unsigned int i, nr_zones;
	unsigned int n = 0;
	int err = -EIO;

	if (!nbfs_sb_has_blkzoned(sbi))
		return 0;

	if (sbi->blocks_per_blkz && sbi->blocks_per_blkz !=
				SECTOR_TO_BLOCK(bdev_zone_sectors(bdev)))
		return -EINVAL;
	sbi->blocks_per_blkz = SECTOR_TO_BLOCK(bdev_zone_sectors(bdev));
	if (sbi->log_blocks_per_blkz && sbi->log_blocks_per_blkz !=
				__ilog2_u32(sbi->blocks_per_blkz))
		return -EINVAL;
	sbi->log_blocks_per_blkz = __ilog2_u32(sbi->blocks_per_blkz);
	FDEV(devi).nr_blkz = SECTOR_TO_BLOCK(nr_sectors) >>
					sbi->log_blocks_per_blkz;
	if (nr_sectors & (bdev_zone_sectors(bdev) - 1))
		FDEV(devi).nr_blkz++;

	FDEV(devi).blkz_type = nbfs_kmalloc(sbi, FDEV(devi).nr_blkz,
								GFP_KERNEL);
	if (!FDEV(devi).blkz_type)
		return -ENOMEM;

#define NBFS_REPORT_NR_ZONES   4096

	zones = nbfs_kzalloc(sbi,
			     array_size(NBFS_REPORT_NR_ZONES,
					sizeof(struct blk_zone)),
			     GFP_KERNEL);
	if (!zones)
		return -ENOMEM;

	/* Get block zones type */
	while (zones && sector < nr_sectors) {

		nr_zones = NBFS_REPORT_NR_ZONES;
		err = blkdev_report_zones(bdev, sector,
					  zones, &nr_zones,
					  GFP_KERNEL);
		if (err)
			break;
		if (!nr_zones) {
			err = -EIO;
			break;
		}

		for (i = 0; i < nr_zones; i++) {
			FDEV(devi).blkz_type[n] = zones[i].type;
			sector += zones[i].len;
			n++;
		}
	}

	kvfree(zones);

	return err;
}
#endif

/*
 * Read nbfs raw super block.
 * Because we have two copies of super block, so read both of them
 * to get the first valid one. If any one of them is broken, we pass
 * them recovery flag back to the caller.
 */
static int read_raw_super_block(struct nbfs_sb_info *sbi,
			struct nbfs_super_block **raw_super,
			int *valid_super_block, int *recovery)
{
	struct super_block *sb = sbi->sb;
	int block;
	struct buffer_head *bh;
	struct nbfs_super_block *super;
	int err = 0;

	super = kzalloc(sizeof(struct nbfs_super_block), GFP_KERNEL);
	if (!super)
		return -ENOMEM;

	for (block = 0; block < 2; block++) {
		bh = sb_bread(sb, block);
		if (!bh) {
			nbfs_msg(sb, KERN_ERR, "Unable to read %dth superblock",
				block + 1);
			err = -EIO;
			continue;
		}

		/* sanity checking of raw super */
		if (sanity_check_raw_super(sbi, bh)) {
			nbfs_msg(sb, KERN_ERR,
				"Can't find valid NBFS filesystem in %dth superblock",
				block + 1);
			err = -EINVAL;
			brelse(bh);
			continue;
		}

		if (!*raw_super) {
			memcpy(super, bh->b_data + NBFS_SUPER_OFFSET,
							sizeof(*super));
			*valid_super_block = block;
			*raw_super = super;
		}
		brelse(bh);
	}

	/* Fail to read any one of the superblocks*/
	if (err < 0)
		*recovery = 1;

	/* No valid superblock */
	if (!*raw_super)
		kvfree(super);
	else
		err = 0;

	return err;
}

int nbfs_commit_super(struct nbfs_sb_info *sbi, bool recover)
{
	struct buffer_head *bh;
	__u32 crc = 0;
	int err;

	if ((recover && nbfs_readonly(sbi->sb)) ||
				bdev_read_only(sbi->sb->s_bdev)) {
		set_sbi_flag(sbi, SBI_NEED_SB_WRITE);
		return -EROFS;
	}

	/* we should update superblock crc here */
	if (!recover && nbfs_sb_has_sb_chksum(sbi)) {
		crc = nbfs_crc32(sbi, NBFS_RAW_SUPER(sbi),
				offsetof(struct nbfs_super_block, crc));
		NBFS_RAW_SUPER(sbi)->crc = cpu_to_le32(crc);
	}

	/* write back-up superblock first */
	bh = sb_bread(sbi->sb, sbi->valid_super_block ? 0 : 1);
	if (!bh)
		return -EIO;
	err = __nbfs_commit_super(bh, NBFS_RAW_SUPER(sbi));
	brelse(bh);

	/* if we are in recovery path, skip writing valid superblock */
	if (recover || err)
		return err;

	/* write current valid superblock */
	bh = sb_bread(sbi->sb, sbi->valid_super_block);
	if (!bh)
		return -EIO;
	err = __nbfs_commit_super(bh, NBFS_RAW_SUPER(sbi));
	brelse(bh);
	return err;
}

static int nbfs_scan_devices(struct nbfs_sb_info *sbi)
{
	struct nbfs_super_block *raw_super = NBFS_RAW_SUPER(sbi);
	unsigned int max_devices = MAX_DEVICES;
	int i;

	/* Initialize single device information */
	if (!RDEV(0).path[0]) {
		if (!bdev_is_zoned(sbi->sb->s_bdev))
			return 0;
		max_devices = 1;
	}

	/*
	 * Initialize multiple devices information, or single
	 * zoned block device information.
	 */
	sbi->devs = nbfs_kzalloc(sbi,
				 array_size(max_devices,
					    sizeof(struct nbfs_dev_info)),
				 GFP_KERNEL);
	if (!sbi->devs)
		return -ENOMEM;

	for (i = 0; i < max_devices; i++) {

		if (i > 0 && !RDEV(i).path[0])
			break;

		if (max_devices == 1) {
			/* Single zoned block device mount */
			FDEV(0).bdev =
				blkdev_get_by_dev(sbi->sb->s_bdev->bd_dev,
					sbi->sb->s_mode, sbi->sb->s_type);
		} else {
			/* Multi-device mount */
			memcpy(FDEV(i).path, RDEV(i).path, MAX_PATH_LEN);
			FDEV(i).total_segments =
				le32_to_cpu(RDEV(i).total_segments);
			if (i == 0) {
				FDEV(i).start_blk = 0;
				FDEV(i).end_blk = FDEV(i).start_blk +
				    (FDEV(i).total_segments <<
				    sbi->log_blocks_per_seg) - 1 +
				    le32_to_cpu(raw_super->segment0_blkaddr);
			} else {
				FDEV(i).start_blk = FDEV(i - 1).end_blk + 1;
				FDEV(i).end_blk = FDEV(i).start_blk +
					(FDEV(i).total_segments <<
					sbi->log_blocks_per_seg) - 1;
			}
			FDEV(i).bdev = blkdev_get_by_path(FDEV(i).path,
					sbi->sb->s_mode, sbi->sb->s_type);
		}
		if (IS_ERR(FDEV(i).bdev))
			return PTR_ERR(FDEV(i).bdev);

		/* to release errored devices */
		sbi->s_ndevs = i + 1;

#ifdef CONFIG_BLK_DEV_ZONED
		if (bdev_zoned_model(FDEV(i).bdev) == BLK_ZONED_HM &&
				!nbfs_sb_has_blkzoned(sbi)) {
			nbfs_msg(sbi->sb, KERN_ERR,
				"Zoned block device feature not enabled\n");
			return -EINVAL;
		}
		if (bdev_zoned_model(FDEV(i).bdev) != BLK_ZONED_NONE) {
			if (init_blkz_info(sbi, i)) {
				nbfs_msg(sbi->sb, KERN_ERR,
					"Failed to initialize NBFS blkzone information");
				return -EINVAL;
			}
			if (max_devices == 1)
				break;
			nbfs_msg(sbi->sb, KERN_INFO,
				"Mount Device [%2d]: %20s, %8u, %8x - %8x (zone: %s)",
				i, FDEV(i).path,
				FDEV(i).total_segments,
				FDEV(i).start_blk, FDEV(i).end_blk,
				bdev_zoned_model(FDEV(i).bdev) == BLK_ZONED_HA ?
				"Host-aware" : "Host-managed");
			continue;
		}
#endif
		nbfs_msg(sbi->sb, KERN_INFO,
			"Mount Device [%2d]: %20s, %8u, %8x - %8x",
				i, FDEV(i).path,
				FDEV(i).total_segments,
				FDEV(i).start_blk, FDEV(i).end_blk);
	}
	nbfs_msg(sbi->sb, KERN_INFO,
			"IO Block Size: %8d KB", NBFS_IO_SIZE_KB(sbi));
	return 0;
}

static void nbfs_tuning_parameters(struct nbfs_sb_info *sbi)
{
	struct nbfs_sm_info *sm_i = SM_I(sbi);

	/* adjust parameters according to the volume size */
	if (sm_i->main_segments <= SMALL_VOLUME_SEGMENTS) {
		NBFS_OPTION(sbi).alloc_mode = ALLOC_MODE_REUSE;
		sm_i->dcc_info->discard_granularity = 1;
		sm_i->ipu_policy = 1 << NBFS_IPU_FORCE;
	}

	sbi->readdir_ra = 1;
}

static int nbfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct nbfs_sb_info *sbi;
	struct nbfs_super_block *raw_super;
	struct inode *root;
	int err;
	bool skip_recovery = false, need_fsck = false;
	char *options = NULL;
	int recovery, i, valid_super_block;
	struct curseg_info *seg_i;
	int retry_cnt = 1;

try_onemore:
	err = -EINVAL;
	raw_super = NULL;
	valid_super_block = -1;
	recovery = 0;

	/* allocate memory for nbfs-specific super block info */
	sbi = kzalloc(sizeof(struct nbfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->sb = sb;

	/* Load the checksum driver */
	sbi->s_chksum_driver = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(sbi->s_chksum_driver)) {
		nbfs_msg(sb, KERN_ERR, "Cannot load crc32 driver.");
		err = PTR_ERR(sbi->s_chksum_driver);
		sbi->s_chksum_driver = NULL;
		goto free_sbi;
	}

	/* set a block size */
	if (unlikely(!sb_set_blocksize(sb, NBFS_BLKSIZE))) {
		nbfs_msg(sb, KERN_ERR, "unable to set blocksize");
		goto free_sbi;
	}

	err = read_raw_super_block(sbi, &raw_super, &valid_super_block,
								&recovery);
	if (err)
		goto free_sbi;

	sb->s_fs_info = sbi;
	sbi->raw_super = raw_super;

	/* precompute checksum seed for metadata */
	if (nbfs_sb_has_inode_chksum(sbi))
		sbi->s_chksum_seed = nbfs_chksum(sbi, ~0, raw_super->uuid,
						sizeof(raw_super->uuid));

	/*
	 * The BLKZONED feature indicates that the drive was formatted with
	 * zone alignment optimization. This is optional for host-aware
	 * devices, but mandatory for host-managed zoned block devices.
	 */
#ifndef CONFIG_BLK_DEV_ZONED
	if (nbfs_sb_has_blkzoned(sbi)) {
		nbfs_msg(sb, KERN_ERR,
			 "Zoned block device support is not enabled\n");
		err = -EOPNOTSUPP;
		goto free_sb_buf;
	}
#endif
	default_options(sbi);
	/* parse mount options */
	options = kstrdup((const char *)data, GFP_KERNEL);
	if (data && !options) {
		err = -ENOMEM;
		goto free_sb_buf;
	}

	err = parse_options(sb, options);
	if (err)
		goto free_options;

	sbi->max_file_blocks = max_file_blocks();
	sb->s_maxbytes = sbi->max_file_blocks <<
				le32_to_cpu(raw_super->log_blocksize);
	sb->s_max_links = NBFS_LINK_MAX;

#ifdef CONFIG_QUOTA
	sb->dq_op = &nbfs_quota_operations;
	if (nbfs_sb_has_quota_ino(sbi))
		sb->s_qcop = &dquot_quotactl_sysfile_ops;
	else
		sb->s_qcop = &nbfs_quotactl_ops;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;

	if (nbfs_sb_has_quota_ino(sbi)) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if (nbfs_qf_ino(sbi->sb, i))
				sbi->nquota_files++;
		}
	}
#endif

	sb->s_op = &nbfs_sops;
#ifdef CONFIG_FS_ENCRYPTION
	sb->s_cop = &nbfs_cryptops;
#endif
	sb->s_xattr = nbfs_xattr_handlers;
	sb->s_export_op = &nbfs_export_ops;
	sb->s_magic = F2FS_SUPER_MAGIC;
	sb->s_time_gran = 1;
	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) |
		(test_opt(sbi, POSIX_ACL) ? SB_POSIXACL : 0);
	memcpy(&sb->s_uuid, raw_super->uuid, sizeof(raw_super->uuid));
	sb->s_iflags |= SB_I_CGROUPWB;

	/* init nbfs-specific super block info */
	sbi->valid_super_block = valid_super_block;
	mutex_init(&sbi->gc_mutex);
	mutex_init(&sbi->writepages);
	mutex_init(&sbi->cp_mutex);
	init_rwsem(&sbi->node_write);
	init_rwsem(&sbi->node_change);

	/* disallow all the data/node/meta page writes */
	set_sbi_flag(sbi, SBI_POR_DOING);
	spin_lock_init(&sbi->stat_lock);

	/* init iostat info */
	spin_lock_init(&sbi->iostat_lock);
	sbi->iostat_enable = false;

	for (i = 0; i < NR_PAGE_TYPE; i++) {
		int n = (i == META) ? 1: NR_TEMP_TYPE;
		int j;

		sbi->write_io[i] =
			nbfs_kmalloc(sbi,
				     array_size(n,
						sizeof(struct nbfs_bio_info)),
				     GFP_KERNEL);
		if (!sbi->write_io[i]) {
			err = -ENOMEM;
			goto free_bio_info;
		}

		for (j = HOT; j < n; j++) {
			init_rwsem(&sbi->write_io[i][j].io_rwsem);
			sbi->write_io[i][j].sbi = sbi;
			sbi->write_io[i][j].bio = NULL;
			spin_lock_init(&sbi->write_io[i][j].io_lock);
			INIT_LIST_HEAD(&sbi->write_io[i][j].io_list);
		}
	}

	init_rwsem(&sbi->cp_rwsem);
	init_waitqueue_head(&sbi->cp_wait);
	init_sb_info(sbi);

	err = init_percpu_info(sbi);
	if (err)
		goto free_bio_info;

	if (NBFS_IO_SIZE(sbi) > 1) {
		sbi->write_io_dummy =
			mempool_create_page_pool(2 * (NBFS_IO_SIZE(sbi) - 1), 0);
		if (!sbi->write_io_dummy) {
			err = -ENOMEM;
			goto free_percpu;
		}
	}

	/* get an inode for meta space */
	sbi->meta_inode = nbfs_iget(sb, NBFS_META_INO(sbi));
	if (IS_ERR(sbi->meta_inode)) {
		nbfs_msg(sb, KERN_ERR, "Failed to read NBFS meta data inode");
		err = PTR_ERR(sbi->meta_inode);
		goto free_io_dummy;
	}

	err = nbfs_get_valid_checkpoint(sbi);
	if (err) {
		nbfs_msg(sb, KERN_ERR, "Failed to get valid NBFS checkpoint");
		goto free_meta_inode;
	}

	if (__is_set_ckpt_flags(NBFS_CKPT(sbi), CP_QUOTA_NEED_FSCK_FLAG))
		set_sbi_flag(sbi, SBI_QUOTA_NEED_REPAIR);
	if (__is_set_ckpt_flags(NBFS_CKPT(sbi), CP_DISABLED_QUICK_FLAG)) {
		set_sbi_flag(sbi, SBI_CP_DISABLED_QUICK);
		sbi->interval_time[DISABLE_TIME] = DEF_DISABLE_QUICK_INTERVAL;
	}

	/* Initialize device list */
	err = nbfs_scan_devices(sbi);
	if (err) {
		nbfs_msg(sb, KERN_ERR, "Failed to find devices");
		goto free_devices;
	}

	sbi->total_valid_node_count =
				le32_to_cpu(sbi->ckpt->valid_node_count);
	percpu_counter_set(&sbi->total_valid_inode_count,
				le32_to_cpu(sbi->ckpt->valid_inode_count));
	sbi->user_block_count = le64_to_cpu(sbi->ckpt->user_block_count);
	sbi->total_valid_block_count =
				le64_to_cpu(sbi->ckpt->valid_block_count);
	sbi->last_valid_block_count = sbi->total_valid_block_count;
	sbi->reserved_blocks = 0;
	sbi->current_reserved_blocks = 0;
	limit_reserve_root(sbi);

	for (i = 0; i < NR_INODE_TYPE; i++) {
		INIT_LIST_HEAD(&sbi->inode_list[i]);
		spin_lock_init(&sbi->inode_lock[i]);
	}

	nbfs_init_extent_cache_info(sbi);

	nbfs_init_ino_entry_info(sbi);

	nbfs_init_fsync_node_info(sbi);

	/* setup nbfs internal modules */
	err = nbfs_build_segment_manager(sbi);
	if (err) {
		nbfs_msg(sb, KERN_ERR,
			"Failed to initialize NBFS segment manager");
		goto free_sm;
	}
	err = nbfs_build_node_manager(sbi);
	if (err) {
		nbfs_msg(sb, KERN_ERR,
			"Failed to initialize NBFS node manager");
		goto free_nm;
	}

	/* For write statistics */
	if (sb->s_bdev->bd_part)
		sbi->sectors_written_start =
			(u64)part_stat_read(sb->s_bdev->bd_part,
					    sectors[STAT_WRITE]);

	/* Read accumulated write IO statistics if exists */
	seg_i = CURSEG_I(sbi, CURSEG_HOT_NODE);
	if (__exist_node_summaries(sbi))
		sbi->kbytes_written =
			le64_to_cpu(seg_i->journal->info.kbytes_written);

	nbfs_build_gc_manager(sbi);

	err = nbfs_build_stats(sbi);
	if (err)
		goto free_nm;

	/* get an inode for node space */
	sbi->node_inode = nbfs_iget(sb, NBFS_NODE_INO(sbi));
	if (IS_ERR(sbi->node_inode)) {
		nbfs_msg(sb, KERN_ERR, "Failed to read node inode");
		err = PTR_ERR(sbi->node_inode);
		goto free_stats;
	}

	/* read root inode and dentry */
	root = nbfs_iget(sb, NBFS_ROOT_INO(sbi));
	if (IS_ERR(root)) {
		nbfs_msg(sb, KERN_ERR, "Failed to read root inode");
		err = PTR_ERR(root);
		goto free_node_inode;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks ||
			!root->i_size || !root->i_nlink) {
		iput(root);
		err = -EINVAL;
		goto free_node_inode;
	}

	sb->s_root = d_make_root(root); /* allocate root dentry */
	if (!sb->s_root) {
		err = -ENOMEM;
		goto free_node_inode;
	}

	err = nbfs_register_sysfs(sbi);
	if (err)
		goto free_root_inode;

#ifdef CONFIG_QUOTA
	/* Enable quota usage during mount */
	if (nbfs_sb_has_quota_ino(sbi) && !nbfs_readonly(sb)) {
		err = nbfs_enable_quotas(sb);
		if (err)
			nbfs_msg(sb, KERN_ERR,
				"Cannot turn on quotas: error %d", err);
	}
#endif
	/* if there are nt orphan nodes free them */
	err = nbfs_recover_orphan_inodes(sbi);
	if (err)
		goto free_meta;

	if (unlikely(is_set_ckpt_flags(sbi, CP_DISABLED_FLAG)))
		goto reset_checkpoint;

	/* recover fsynced data */
	if (!test_opt(sbi, DISABLE_ROLL_FORWARD)) {
		/*
		 * mount should be failed, when device has readonly mode, and
		 * previous checkpoint was not done by clean system shutdown.
		 */
		if (bdev_read_only(sb->s_bdev) &&
				!is_set_ckpt_flags(sbi, CP_UMOUNT_FLAG)) {
			err = -EROFS;
			goto free_meta;
		}

		if (need_fsck)
			set_sbi_flag(sbi, SBI_NEED_FSCK);

		if (skip_recovery)
			goto reset_checkpoint;

		err = nbfs_recover_fsync_data(sbi, false);
		if (err < 0) {
			if (err != -ENOMEM)
				skip_recovery = true;
			need_fsck = true;
			nbfs_msg(sb, KERN_ERR,
				"Cannot recover all fsync data errno=%d", err);
			goto free_meta;
		}
	} else {
		err = nbfs_recover_fsync_data(sbi, true);

		if (!nbfs_readonly(sb) && err > 0) {
			err = -EINVAL;
			nbfs_msg(sb, KERN_ERR,
				"Need to recover fsync data");
			goto free_meta;
		}
	}
reset_checkpoint:
	/* nbfs_recover_fsync_data() cleared this already */
	clear_sbi_flag(sbi, SBI_POR_DOING);

	if (test_opt(sbi, DISABLE_CHECKPOINT)) {
		err = nbfs_disable_checkpoint(sbi);
		if (err)
			goto sync_free_meta;
	} else if (is_set_ckpt_flags(sbi, CP_DISABLED_FLAG)) {
		nbfs_enable_checkpoint(sbi);
	}

	/*
	 * If filesystem is not mounted as read-only then
	 * do start the gc_thread.
	 */
	if (test_opt(sbi, BG_GC) && !nbfs_readonly(sb)) {
		/* After POR, we can run background GC thread.*/
		err = nbfs_start_gc_thread(sbi);
		if (err)
			goto sync_free_meta;
	}
	kvfree(options);

	/* recover broken superblock */
	if (recovery) {
		err = nbfs_commit_super(sbi, true);
		nbfs_msg(sb, KERN_INFO,
			"Try to recover %dth superblock, ret: %d",
			sbi->valid_super_block ? 1 : 2, err);
	}

	nbfs_join_shrinker(sbi);

	nbfs_tuning_parameters(sbi);

	nbfs_msg(sbi->sb, KERN_NOTICE, "Mounted with checkpoint version = %llx",
				cur_cp_version(NBFS_CKPT(sbi)));
	nbfs_update_time(sbi, CP_TIME);
	nbfs_update_time(sbi, REQ_TIME);
	clear_sbi_flag(sbi, SBI_CP_DISABLED_QUICK);
	nbfs_debug_init(sbi, 0);
	return 0;

sync_free_meta:
	/* safe to flush all the data */
	sync_filesystem(sbi->sb);
	retry_cnt = 0;

free_meta:
#ifdef CONFIG_QUOTA
	nbfs_truncate_quota_inode_pages(sb);
	if (nbfs_sb_has_quota_ino(sbi) && !nbfs_readonly(sb))
		nbfs_quota_off_umount(sbi->sb);
#endif
	/*
	 * Some dirty meta pages can be produced by nbfs_recover_orphan_inodes()
	 * failed by EIO. Then, iput(node_inode) can trigger balance_fs_bg()
	 * followed by nbfs_write_checkpoint() through nbfs_write_node_pages(), which
	 * falls into an infinite loop in nbfs_sync_meta_pages().
	 */
	truncate_inode_pages_final(META_MAPPING(sbi));
	/* evict some inodes being cached by GC */
	evict_inodes(sb);
	nbfs_unregister_sysfs(sbi);
free_root_inode:
	dput(sb->s_root);
	sb->s_root = NULL;
free_node_inode:
	nbfs_release_ino_entry(sbi, true);
	truncate_inode_pages_final(NODE_MAPPING(sbi));
	iput(sbi->node_inode);
	sbi->node_inode = NULL;
free_stats:
	nbfs_destroy_stats(sbi);
free_nm:
	nbfs_destroy_node_manager(sbi);
free_sm:
	nbfs_destroy_segment_manager(sbi);
free_devices:
	destroy_device_list(sbi);
	kvfree(sbi->ckpt);
free_meta_inode:
	make_bad_inode(sbi->meta_inode);
	iput(sbi->meta_inode);
	sbi->meta_inode = NULL;
free_io_dummy:
	mempool_destroy(sbi->write_io_dummy);
free_percpu:
	destroy_percpu_info(sbi);
free_bio_info:
	for (i = 0; i < NR_PAGE_TYPE; i++)
		kvfree(sbi->write_io[i]);
free_options:
#ifdef CONFIG_QUOTA
	for (i = 0; i < MAXQUOTAS; i++)
		kvfree(NBFS_OPTION(sbi).s_qf_names[i]);
#endif
	kvfree(options);
free_sb_buf:
	kvfree(raw_super);
free_sbi:
	if (sbi->s_chksum_driver)
		crypto_free_shash(sbi->s_chksum_driver);
	kvfree(sbi);

	/* give only one another chance */
	if (retry_cnt > 0 && skip_recovery) {
		retry_cnt--;
		shrink_dcache_sb(sb);
		goto try_onemore;
	}
	return err;
}

static struct dentry *nbfs_mount(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, nbfs_fill_super);
}

static void kill_nbfs_super(struct super_block *sb)
{
	nbfs_debug_exit(0);
	if (sb->s_root) {
		struct nbfs_sb_info *sbi = NBFS_SB(sb);

		set_sbi_flag(sbi, SBI_IS_CLOSE);
		nbfs_stop_gc_thread(sbi);
		nbfs_stop_discard_thread(sbi);

		if (is_sbi_flag_set(sbi, SBI_IS_DIRTY) ||
				!is_set_ckpt_flags(sbi, CP_UMOUNT_FLAG)) {
			struct cp_control cpc = {
				.reason = CP_UMOUNT,
			};
			nbfs_write_checkpoint(sbi, &cpc);
		}

		if (is_sbi_flag_set(sbi, SBI_IS_RECOVERED) && nbfs_readonly(sb))
			sb->s_flags &= ~SB_RDONLY;
	}
	kill_block_super(sb);
}

static struct file_system_type nbfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "nbfs",
	.mount		= nbfs_mount,
	.kill_sb	= kill_nbfs_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("nbfs");

static int __init init_inodecache(void)
{
	nbfs_inode_cachep = kmem_cache_create("nbfs_inode_cache",
			sizeof(struct nbfs_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT|SLAB_ACCOUNT, NULL);
	if (!nbfs_inode_cachep)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(nbfs_inode_cachep);
}

static int __init init_nbfs_fs(void)
{
	int err;

	if (PAGE_SIZE != NBFS_BLKSIZE) {
		printk("NBFS not supported on PAGE_SIZE(%lu) != %d\n",
				PAGE_SIZE, NBFS_BLKSIZE);
		return -EINVAL;
	}

	nbfs_build_trace_ios();

	err = init_inodecache();
	if (err)
		goto fail;
	err = nbfs_create_node_manager_caches();
	if (err)
		goto free_inodecache;
	err = nbfs_create_segment_manager_caches();
	if (err)
		goto free_node_manager_caches;
	err = nbfs_create_checkpoint_caches();
	if (err)
		goto free_segment_manager_caches;
	err = nbfs_create_extent_cache();
	if (err)
		goto free_checkpoint_caches;
	err = nbfs_init_sysfs();
	if (err)
		goto free_extent_cache;
	err = register_shrinker(&nbfs_shrinker_info);
	if (err)
		goto free_sysfs;
	err = register_filesystem(&nbfs_fs_type);
	if (err)
		goto free_shrinker;
	nbfs_create_root_stats();
	err = nbfs_init_post_read_processing();
	if (err)
		goto free_root_stats;
	return 0;

free_root_stats:
	nbfs_destroy_root_stats();
	unregister_filesystem(&nbfs_fs_type);
free_shrinker:
	unregister_shrinker(&nbfs_shrinker_info);
free_sysfs:
	nbfs_exit_sysfs();
free_extent_cache:
	nbfs_destroy_extent_cache();
free_checkpoint_caches:
	nbfs_destroy_checkpoint_caches();
free_segment_manager_caches:
	nbfs_destroy_segment_manager_caches();
free_node_manager_caches:
	nbfs_destroy_node_manager_caches();
free_inodecache:
	destroy_inodecache();
fail:
	return err;
}

static void __exit exit_nbfs_fs(void)
{
	nbfs_destroy_post_read_processing();
	nbfs_destroy_root_stats();
	unregister_filesystem(&nbfs_fs_type);
	unregister_shrinker(&nbfs_shrinker_info);
	nbfs_exit_sysfs();
	nbfs_destroy_extent_cache();
	nbfs_destroy_checkpoint_caches();
	nbfs_destroy_segment_manager_caches();
	nbfs_destroy_node_manager_caches();
	destroy_inodecache();
	nbfs_destroy_trace_ios();
}

module_init(init_nbfs_fs)
module_exit(exit_nbfs_fs)

MODULE_AUTHOR("Samsung Electronics's Praesto Team");
MODULE_DESCRIPTION("Flash Friendly File System");
MODULE_LICENSE("GPL");

