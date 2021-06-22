// SPDX-License-Identifier: GPL-2.0
/*
 * nbfs sysfs interface
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2017 Chao Yu <chao@kernel.org>
 */
#include <linux/compiler.h>
#include <linux/proc_fs.h>
#include <linux/nbfs_fs.h>
#include <linux/seq_file.h>

#include "nbfs.h"
#include "segment.h"
#include "gc.h"

static struct proc_dir_entry *nbfs_proc_root;

/* Sysfs support for nbfs */
enum {
	GC_THREAD,	/* struct nbfs_gc_thread */
	SM_INFO,	/* struct nbfs_sm_info */
	DCC_INFO,	/* struct discard_cmd_control */
	NM_INFO,	/* struct nbfs_nm_info */
	NBFS_SBI,	/* struct nbfs_sb_info */
#ifdef CONFIG_NBFS_FAULT_INJECTION
	FAULT_INFO_RATE,	/* struct nbfs_fault_info */
	FAULT_INFO_TYPE,	/* struct nbfs_fault_info */
#endif
	RESERVED_BLOCKS,	/* struct nbfs_sb_info */
};

struct nbfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct nbfs_attr *, struct nbfs_sb_info *, char *);
	ssize_t (*store)(struct nbfs_attr *, struct nbfs_sb_info *,
			 const char *, size_t);
	int struct_type;
	int offset;
	int id;
};

static unsigned char *__struct_ptr(struct nbfs_sb_info *sbi, int struct_type)
{
	if (struct_type == GC_THREAD)
		return (unsigned char *)sbi->gc_thread;
	else if (struct_type == SM_INFO)
		return (unsigned char *)SM_I(sbi);
	else if (struct_type == DCC_INFO)
		return (unsigned char *)SM_I(sbi)->dcc_info;
	else if (struct_type == NM_INFO)
		return (unsigned char *)NM_I(sbi);
	else if (struct_type == NBFS_SBI || struct_type == RESERVED_BLOCKS)
		return (unsigned char *)sbi;
#ifdef CONFIG_NBFS_FAULT_INJECTION
	else if (struct_type == FAULT_INFO_RATE ||
					struct_type == FAULT_INFO_TYPE)
		return (unsigned char *)&NBFS_OPTION(sbi).fault_info;
#endif
	return NULL;
}

static ssize_t dirty_segments_show(struct nbfs_attr *a,
		struct nbfs_sb_info *sbi, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n",
		(unsigned long long)(dirty_segments(sbi)));
}

static ssize_t lifetime_write_kbytes_show(struct nbfs_attr *a,
		struct nbfs_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->sb;

	if (!sb->s_bdev->bd_part)
		return snprintf(buf, PAGE_SIZE, "0\n");

	return snprintf(buf, PAGE_SIZE, "%llu\n",
		(unsigned long long)(sbi->kbytes_written +
			BD_PART_WRITTEN(sbi)));
}

static ssize_t features_show(struct nbfs_attr *a,
		struct nbfs_sb_info *sbi, char *buf)
{
	struct super_block *sb = sbi->sb;
	int len = 0;

	if (!sb->s_bdev->bd_part)
		return snprintf(buf, PAGE_SIZE, "0\n");

	if (nbfs_sb_has_encrypt(sbi))
		len += snprintf(buf, PAGE_SIZE - len, "%s",
						"encryption");
	if (nbfs_sb_has_blkzoned(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "blkzoned");
	if (nbfs_sb_has_extra_attr(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "extra_attr");
	if (nbfs_sb_has_project_quota(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "projquota");
	if (nbfs_sb_has_inode_chksum(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "inode_checksum");
	if (nbfs_sb_has_flexible_inline_xattr(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "flexible_inline_xattr");
	if (nbfs_sb_has_quota_ino(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "quota_ino");
	if (nbfs_sb_has_inode_crtime(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "inode_crtime");
	if (nbfs_sb_has_lost_found(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "lost_found");
	if (nbfs_sb_has_sb_chksum(sbi))
		len += snprintf(buf + len, PAGE_SIZE - len, "%s%s",
				len ? ", " : "", "sb_checksum");
	len += snprintf(buf + len, PAGE_SIZE - len, "\n");
	return len;
}

static ssize_t current_reserved_blocks_show(struct nbfs_attr *a,
					struct nbfs_sb_info *sbi, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->current_reserved_blocks);
}

static ssize_t nbfs_sbi_show(struct nbfs_attr *a,
			struct nbfs_sb_info *sbi, char *buf)
{
	unsigned char *ptr = NULL;
	unsigned int *ui;

	ptr = __struct_ptr(sbi, a->struct_type);
	if (!ptr)
		return -EINVAL;

	if (!strcmp(a->attr.name, "extension_list")) {
		__u8 (*extlist)[NBFS_EXTENSION_LEN] =
					sbi->raw_super->extension_list;
		int cold_count = le32_to_cpu(sbi->raw_super->extension_count);
		int hot_count = sbi->raw_super->hot_ext_count;
		int len = 0, i;

		len += snprintf(buf + len, PAGE_SIZE - len,
						"cold file extension:\n");
		for (i = 0; i < cold_count; i++)
			len += snprintf(buf + len, PAGE_SIZE - len, "%s\n",
								extlist[i]);

		len += snprintf(buf + len, PAGE_SIZE - len,
						"hot file extension:\n");
		for (i = cold_count; i < cold_count + hot_count; i++)
			len += snprintf(buf + len, PAGE_SIZE - len, "%s\n",
								extlist[i]);
		return len;
	}

	ui = (unsigned int *)(ptr + a->offset);

	return snprintf(buf, PAGE_SIZE, "%u\n", *ui);
}

static ssize_t __sbi_store(struct nbfs_attr *a,
			struct nbfs_sb_info *sbi,
			const char *buf, size_t count)
{
	unsigned char *ptr;
	unsigned long t;
	unsigned int *ui;
	ssize_t ret;

	ptr = __struct_ptr(sbi, a->struct_type);
	if (!ptr)
		return -EINVAL;

	if (!strcmp(a->attr.name, "extension_list")) {
		const char *name = strim((char *)buf);
		bool set = true, hot;

		if (!strncmp(name, "[h]", 3))
			hot = true;
		else if (!strncmp(name, "[c]", 3))
			hot = false;
		else
			return -EINVAL;

		name += 3;

		if (*name == '!') {
			name++;
			set = false;
		}

		if (strlen(name) >= NBFS_EXTENSION_LEN)
			return -EINVAL;

		down_write(&sbi->sb_lock);

		ret = nbfs_update_extension_list(sbi, name, hot, set);
		if (ret)
			goto out;

		ret = nbfs_commit_super(sbi, false);
		if (ret)
			nbfs_update_extension_list(sbi, name, hot, !set);
out:
		up_write(&sbi->sb_lock);
		return ret ? ret : count;
	}

	ui = (unsigned int *)(ptr + a->offset);

	ret = kstrtoul(skip_spaces(buf), 0, &t);
	if (ret < 0)
		return ret;
#ifdef CONFIG_NBFS_FAULT_INJECTION
	if (a->struct_type == FAULT_INFO_TYPE && t >= (1 << FAULT_MAX))
		return -EINVAL;
	if (a->struct_type == FAULT_INFO_RATE && t >= UINT_MAX)
		return -EINVAL;
#endif
	if (a->struct_type == RESERVED_BLOCKS) {
		spin_lock(&sbi->stat_lock);
		if (t > (unsigned long)(sbi->user_block_count -
				NBFS_OPTION(sbi).root_reserved_blocks)) {
			spin_unlock(&sbi->stat_lock);
			return -EINVAL;
		}
		*ui = t;
		sbi->current_reserved_blocks = min(sbi->reserved_blocks,
				sbi->user_block_count - valid_user_blocks(sbi));
		spin_unlock(&sbi->stat_lock);
		return count;
	}

	if (!strcmp(a->attr.name, "discard_granularity")) {
		if (t == 0 || t > MAX_PLIST_NUM)
			return -EINVAL;
		if (t == *ui)
			return count;
		*ui = t;
		return count;
	}

	if (!strcmp(a->attr.name, "migration_granularity")) {
		if (t == 0 || t > sbi->segs_per_sec)
			return -EINVAL;
	}

	if (!strcmp(a->attr.name, "trim_sections"))
		return -EINVAL;

	if (!strcmp(a->attr.name, "gc_urgent")) {
		if (t >= 1) {
			sbi->gc_mode = GC_URGENT;
			if (sbi->gc_thread) {
				sbi->gc_thread->gc_wake = 1;
				wake_up_interruptible_all(
					&sbi->gc_thread->gc_wait_queue_head);
				wake_up_discard_thread(sbi, true);
			}
		} else {
			sbi->gc_mode = GC_NORMAL;
		}
		return count;
	}
	if (!strcmp(a->attr.name, "gc_idle")) {
		if (t == GC_IDLE_CB)
			sbi->gc_mode = GC_IDLE_CB;
		else if (t == GC_IDLE_GREEDY)
			sbi->gc_mode = GC_IDLE_GREEDY;
		else
			sbi->gc_mode = GC_NORMAL;
		return count;
	}


	if (!strcmp(a->attr.name, "iostat_enable")) {
		sbi->iostat_enable = !!t;
		if (!sbi->iostat_enable)
			nbfs_reset_iostat(sbi);
		return count;
	}

	*ui = (unsigned int)t;

	return count;
}

static ssize_t nbfs_sbi_store(struct nbfs_attr *a,
			struct nbfs_sb_info *sbi,
			const char *buf, size_t count)
{
	ssize_t ret;
	bool gc_entry = (!strcmp(a->attr.name, "gc_urgent") ||
					a->struct_type == GC_THREAD);

	if (gc_entry) {
		if (!down_read_trylock(&sbi->sb->s_umount))
			return -EAGAIN;
	}
	ret = __sbi_store(a, sbi, buf, count);
	if (gc_entry)
		up_read(&sbi->sb->s_umount);

	return ret;
}

static ssize_t nbfs_attr_show(struct kobject *kobj,
				struct attribute *attr, char *buf)
{
	struct nbfs_sb_info *sbi = container_of(kobj, struct nbfs_sb_info,
								s_kobj);
	struct nbfs_attr *a = container_of(attr, struct nbfs_attr, attr);

	return a->show ? a->show(a, sbi, buf) : 0;
}

static ssize_t nbfs_attr_store(struct kobject *kobj, struct attribute *attr,
						const char *buf, size_t len)
{
	struct nbfs_sb_info *sbi = container_of(kobj, struct nbfs_sb_info,
									s_kobj);
	struct nbfs_attr *a = container_of(attr, struct nbfs_attr, attr);

	return a->store ? a->store(a, sbi, buf, len) : 0;
}

static void nbfs_sb_release(struct kobject *kobj)
{
	struct nbfs_sb_info *sbi = container_of(kobj, struct nbfs_sb_info,
								s_kobj);
	complete(&sbi->s_kobj_unregister);
}

enum feat_id {
	FEAT_CRYPTO = 0,
	FEAT_BLKZONED,
	FEAT_ATOMIC_WRITE,
	FEAT_EXTRA_ATTR,
	FEAT_PROJECT_QUOTA,
	FEAT_INODE_CHECKSUM,
	FEAT_FLEXIBLE_INLINE_XATTR,
	FEAT_QUOTA_INO,
	FEAT_INODE_CRTIME,
	FEAT_LOST_FOUND,
	FEAT_SB_CHECKSUM,
};

static ssize_t nbfs_feature_show(struct nbfs_attr *a,
		struct nbfs_sb_info *sbi, char *buf)
{
	switch (a->id) {
	case FEAT_CRYPTO:
	case FEAT_BLKZONED:
	case FEAT_ATOMIC_WRITE:
	case FEAT_EXTRA_ATTR:
	case FEAT_PROJECT_QUOTA:
	case FEAT_INODE_CHECKSUM:
	case FEAT_FLEXIBLE_INLINE_XATTR:
	case FEAT_QUOTA_INO:
	case FEAT_INODE_CRTIME:
	case FEAT_LOST_FOUND:
	case FEAT_SB_CHECKSUM:
		return snprintf(buf, PAGE_SIZE, "supported\n");
	}
	return 0;
}

#define NBFS_ATTR_OFFSET(_struct_type, _name, _mode, _show, _store, _offset) \
static struct nbfs_attr nbfs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
	.struct_type = _struct_type,				\
	.offset = _offset					\
}

#define NBFS_RW_ATTR(struct_type, struct_name, name, elname)	\
	NBFS_ATTR_OFFSET(struct_type, name, 0644,		\
		nbfs_sbi_show, nbfs_sbi_store,			\
		offsetof(struct struct_name, elname))

#define NBFS_GENERAL_RO_ATTR(name) \
static struct nbfs_attr nbfs_attr_##name = __ATTR(name, 0444, name##_show, NULL)

#define NBFS_FEATURE_RO_ATTR(_name, _id)			\
static struct nbfs_attr nbfs_attr_##_name = {			\
	.attr = {.name = __stringify(_name), .mode = 0444 },	\
	.show	= nbfs_feature_show,				\
	.id	= _id,						\
}

NBFS_RW_ATTR(GC_THREAD, nbfs_gc_kthread, gc_urgent_sleep_time,
							urgent_sleep_time);
NBFS_RW_ATTR(GC_THREAD, nbfs_gc_kthread, gc_min_sleep_time, min_sleep_time);
NBFS_RW_ATTR(GC_THREAD, nbfs_gc_kthread, gc_max_sleep_time, max_sleep_time);
NBFS_RW_ATTR(GC_THREAD, nbfs_gc_kthread, gc_no_gc_sleep_time, no_gc_sleep_time);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, gc_idle, gc_mode);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, gc_urgent, gc_mode);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, reclaim_segments, rec_prefree_segments);
NBFS_RW_ATTR(DCC_INFO, discard_cmd_control, max_small_discards, max_discards);
NBFS_RW_ATTR(DCC_INFO, discard_cmd_control, discard_granularity, discard_granularity);
NBFS_RW_ATTR(RESERVED_BLOCKS, nbfs_sb_info, reserved_blocks, reserved_blocks);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, batched_trim_sections, trim_sections);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, ipu_policy, ipu_policy);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, min_ipu_util, min_ipu_util);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, min_fsync_blocks, min_fsync_blocks);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, min_seq_blocks, min_seq_blocks);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, min_hot_blocks, min_hot_blocks);
NBFS_RW_ATTR(SM_INFO, nbfs_sm_info, min_ssr_sections, min_ssr_sections);
NBFS_RW_ATTR(NM_INFO, nbfs_nm_info, ram_thresh, ram_thresh);
NBFS_RW_ATTR(NM_INFO, nbfs_nm_info, ra_nid_pages, ra_nid_pages);
NBFS_RW_ATTR(NM_INFO, nbfs_nm_info, dirty_nats_ratio, dirty_nats_ratio);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, max_victim_search, max_victim_search);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, migration_granularity, migration_granularity);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, dir_level, dir_level);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, cp_interval, interval_time[CP_TIME]);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, idle_interval, interval_time[REQ_TIME]);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, discard_idle_interval,
					interval_time[DISCARD_TIME]);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, gc_idle_interval, interval_time[GC_TIME]);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info,
		umount_discard_timeout, interval_time[UMOUNT_DISCARD_TIMEOUT]);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, iostat_enable, iostat_enable);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, readdir_ra, readdir_ra);
NBFS_RW_ATTR(NBFS_SBI, nbfs_sb_info, gc_pin_file_thresh, gc_pin_file_threshold);
NBFS_RW_ATTR(NBFS_SBI, nbfs_super_block, extension_list, extension_list);
#ifdef CONFIG_NBFS_FAULT_INJECTION
NBFS_RW_ATTR(FAULT_INFO_RATE, nbfs_fault_info, inject_rate, inject_rate);
NBFS_RW_ATTR(FAULT_INFO_TYPE, nbfs_fault_info, inject_type, inject_type);
#endif
NBFS_GENERAL_RO_ATTR(dirty_segments);
NBFS_GENERAL_RO_ATTR(lifetime_write_kbytes);
NBFS_GENERAL_RO_ATTR(features);
NBFS_GENERAL_RO_ATTR(current_reserved_blocks);

#ifdef CONFIG_FS_ENCRYPTION
NBFS_FEATURE_RO_ATTR(encryption, FEAT_CRYPTO);
#endif
#ifdef CONFIG_BLK_DEV_ZONED
NBFS_FEATURE_RO_ATTR(block_zoned, FEAT_BLKZONED);
#endif
NBFS_FEATURE_RO_ATTR(atomic_write, FEAT_ATOMIC_WRITE);
NBFS_FEATURE_RO_ATTR(extra_attr, FEAT_EXTRA_ATTR);
NBFS_FEATURE_RO_ATTR(project_quota, FEAT_PROJECT_QUOTA);
NBFS_FEATURE_RO_ATTR(inode_checksum, FEAT_INODE_CHECKSUM);
NBFS_FEATURE_RO_ATTR(flexible_inline_xattr, FEAT_FLEXIBLE_INLINE_XATTR);
NBFS_FEATURE_RO_ATTR(quota_ino, FEAT_QUOTA_INO);
NBFS_FEATURE_RO_ATTR(inode_crtime, FEAT_INODE_CRTIME);
NBFS_FEATURE_RO_ATTR(lost_found, FEAT_LOST_FOUND);
NBFS_FEATURE_RO_ATTR(sb_checksum, FEAT_SB_CHECKSUM);

#define ATTR_LIST(name) (&nbfs_attr_##name.attr)
static struct attribute *nbfs_attrs[] = {
	ATTR_LIST(gc_urgent_sleep_time),
	ATTR_LIST(gc_min_sleep_time),
	ATTR_LIST(gc_max_sleep_time),
	ATTR_LIST(gc_no_gc_sleep_time),
	ATTR_LIST(gc_idle),
	ATTR_LIST(gc_urgent),
	ATTR_LIST(reclaim_segments),
	ATTR_LIST(max_small_discards),
	ATTR_LIST(discard_granularity),
	ATTR_LIST(batched_trim_sections),
	ATTR_LIST(ipu_policy),
	ATTR_LIST(min_ipu_util),
	ATTR_LIST(min_fsync_blocks),
	ATTR_LIST(min_seq_blocks),
	ATTR_LIST(min_hot_blocks),
	ATTR_LIST(min_ssr_sections),
	ATTR_LIST(max_victim_search),
	ATTR_LIST(migration_granularity),
	ATTR_LIST(dir_level),
	ATTR_LIST(ram_thresh),
	ATTR_LIST(ra_nid_pages),
	ATTR_LIST(dirty_nats_ratio),
	ATTR_LIST(cp_interval),
	ATTR_LIST(idle_interval),
	ATTR_LIST(discard_idle_interval),
	ATTR_LIST(gc_idle_interval),
	ATTR_LIST(umount_discard_timeout),
	ATTR_LIST(iostat_enable),
	ATTR_LIST(readdir_ra),
	ATTR_LIST(gc_pin_file_thresh),
	ATTR_LIST(extension_list),
#ifdef CONFIG_NBFS_FAULT_INJECTION
	ATTR_LIST(inject_rate),
	ATTR_LIST(inject_type),
#endif
	ATTR_LIST(dirty_segments),
	ATTR_LIST(lifetime_write_kbytes),
	ATTR_LIST(features),
	ATTR_LIST(reserved_blocks),
	ATTR_LIST(current_reserved_blocks),
	NULL,
};

static struct attribute *nbfs_feat_attrs[] = {
#ifdef CONFIG_FS_ENCRYPTION
	ATTR_LIST(encryption),
#endif
#ifdef CONFIG_BLK_DEV_ZONED
	ATTR_LIST(block_zoned),
#endif
	ATTR_LIST(atomic_write),
	ATTR_LIST(extra_attr),
	ATTR_LIST(project_quota),
	ATTR_LIST(inode_checksum),
	ATTR_LIST(flexible_inline_xattr),
	ATTR_LIST(quota_ino),
	ATTR_LIST(inode_crtime),
	ATTR_LIST(lost_found),
	ATTR_LIST(sb_checksum),
	NULL,
};

static const struct sysfs_ops nbfs_attr_ops = {
	.show	= nbfs_attr_show,
	.store	= nbfs_attr_store,
};

static struct kobj_type nbfs_sb_ktype = {
	.default_attrs	= nbfs_attrs,
	.sysfs_ops	= &nbfs_attr_ops,
	.release	= nbfs_sb_release,
};

static struct kobj_type nbfs_ktype = {
	.sysfs_ops	= &nbfs_attr_ops,
};

static struct kset nbfs_kset = {
	.kobj   = {.ktype = &nbfs_ktype},
};

static struct kobj_type nbfs_feat_ktype = {
	.default_attrs	= nbfs_feat_attrs,
	.sysfs_ops	= &nbfs_attr_ops,
};

static struct kobject nbfs_feat = {
	.kset	= &nbfs_kset,
};

static int __maybe_unused segment_info_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	unsigned int total_segs =
			le32_to_cpu(sbi->raw_super->segment_count_main);
	int i;

	seq_puts(seq, "format: segment_type|valid_blocks\n"
		"segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)\n");

	for (i = 0; i < total_segs; i++) {
		struct seg_entry *se = get_seg_entry(sbi, i);

		if ((i % 10) == 0)
			seq_printf(seq, "%-10d", i);
		seq_printf(seq, "%d|%-3u", se->type,
					get_valid_blocks(sbi, i, false));
		if ((i % 10) == 9 || i == (total_segs - 1))
			seq_putc(seq, '\n');
		else
			seq_putc(seq, ' ');
	}

	return 0;
}

static int __maybe_unused segment_bits_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	unsigned int total_segs =
			le32_to_cpu(sbi->raw_super->segment_count_main);
	int i, j;

	seq_puts(seq, "format: segment_type|valid_blocks|bitmaps\n"
		"segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)\n");

	for (i = 0; i < total_segs; i++) {
		struct seg_entry *se = get_seg_entry(sbi, i);

		seq_printf(seq, "%-10d", i);
		seq_printf(seq, "%d|%-3u|", se->type,
					get_valid_blocks(sbi, i, false));
		for (j = 0; j < SIT_VBLOCK_MAP_SIZE; j++)
			seq_printf(seq, " %.2x", se->cur_valid_map[j]);
		seq_putc(seq, '\n');
	}
	return 0;
}

static int __maybe_unused iostat_info_seq_show(struct seq_file *seq,
					       void *offset)
{
	struct super_block *sb = seq->private;
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	time64_t now = ktime_get_real_seconds();

	if (!sbi->iostat_enable)
		return 0;

	seq_printf(seq, "time:		%-16llu\n", now);

	/* print app IOs */
	seq_printf(seq, "app buffered:	%-16llu\n",
				sbi->write_iostat[APP_BUFFERED_IO]);
	seq_printf(seq, "app direct:	%-16llu\n",
				sbi->write_iostat[APP_DIRECT_IO]);
	seq_printf(seq, "app mapped:	%-16llu\n",
				sbi->write_iostat[APP_MAPPED_IO]);

	/* print fs IOs */
	seq_printf(seq, "fs data:	%-16llu\n",
				sbi->write_iostat[FS_DATA_IO]);
	seq_printf(seq, "fs node:	%-16llu\n",
				sbi->write_iostat[FS_NODE_IO]);
	seq_printf(seq, "fs meta:	%-16llu\n",
				sbi->write_iostat[FS_META_IO]);
	seq_printf(seq, "fs gc data:	%-16llu\n",
				sbi->write_iostat[FS_GC_DATA_IO]);
	seq_printf(seq, "fs gc node:	%-16llu\n",
				sbi->write_iostat[FS_GC_NODE_IO]);
	seq_printf(seq, "fs cp data:	%-16llu\n",
				sbi->write_iostat[FS_CP_DATA_IO]);
	seq_printf(seq, "fs cp node:	%-16llu\n",
				sbi->write_iostat[FS_CP_NODE_IO]);
	seq_printf(seq, "fs cp meta:	%-16llu\n",
				sbi->write_iostat[FS_CP_META_IO]);
	seq_printf(seq, "fs discard:	%-16llu\n",
				sbi->write_iostat[FS_DISCARD]);

	return 0;
}

static int __maybe_unused victim_bits_seq_show(struct seq_file *seq,
						void *offset)
{
	struct super_block *sb = seq->private;
	struct nbfs_sb_info *sbi = NBFS_SB(sb);
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	int i;

	seq_puts(seq, "format: victim_secmap bitmaps\n");

	for (i = 0; i < MAIN_SECS(sbi); i++) {
		if ((i % 10) == 0)
			seq_printf(seq, "%-10d", i);
		seq_printf(seq, "%d", test_bit(i, dirty_i->victim_secmap) ? 1 : 0);
		if ((i % 10) == 9 || i == (MAIN_SECS(sbi) - 1))
			seq_putc(seq, '\n');
		else
			seq_putc(seq, ' ');
	}
	return 0;
}

int __init nbfs_init_sysfs(void)
{
	int ret;

	kobject_set_name(&nbfs_kset.kobj, "nbfs");
	nbfs_kset.kobj.parent = fs_kobj;
	ret = kset_register(&nbfs_kset);
	if (ret)
		return ret;

	ret = kobject_init_and_add(&nbfs_feat, &nbfs_feat_ktype,
				   NULL, "features");
	if (ret)
		kset_unregister(&nbfs_kset);
	else
		nbfs_proc_root = proc_mkdir("fs/nbfs", NULL);
	return ret;
}

void nbfs_exit_sysfs(void)
{
	kobject_put(&nbfs_feat);
	kset_unregister(&nbfs_kset);
	remove_proc_entry("fs/nbfs", NULL);
	nbfs_proc_root = NULL;
}

int nbfs_register_sysfs(struct nbfs_sb_info *sbi)
{
	struct super_block *sb = sbi->sb;
	int err;

	sbi->s_kobj.kset = &nbfs_kset;
	init_completion(&sbi->s_kobj_unregister);
	err = kobject_init_and_add(&sbi->s_kobj, &nbfs_sb_ktype, NULL,
				"%s", sb->s_id);
	if (err)
		return err;

	if (nbfs_proc_root)
		sbi->s_proc = proc_mkdir(sb->s_id, nbfs_proc_root);

	if (sbi->s_proc) {
		proc_create_single_data("segment_info", S_IRUGO, sbi->s_proc,
				segment_info_seq_show, sb);
		proc_create_single_data("segment_bits", S_IRUGO, sbi->s_proc,
				segment_bits_seq_show, sb);
		proc_create_single_data("iostat_info", S_IRUGO, sbi->s_proc,
				iostat_info_seq_show, sb);
		proc_create_single_data("victim_bits", S_IRUGO, sbi->s_proc,
				victim_bits_seq_show, sb);
	}
	return 0;
}

void nbfs_unregister_sysfs(struct nbfs_sb_info *sbi)
{
	if (sbi->s_proc) {
		remove_proc_entry("iostat_info", sbi->s_proc);
		remove_proc_entry("segment_info", sbi->s_proc);
		remove_proc_entry("segment_bits", sbi->s_proc);
		remove_proc_entry("victim_bits", sbi->s_proc);
		remove_proc_entry(sbi->sb->s_id, nbfs_proc_root);
	}
	kobject_del(&sbi->s_kobj);
}
