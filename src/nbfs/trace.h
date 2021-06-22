// SPDX-License-Identifier: GPL-2.0
/*
 * nbfs IO tracer
 *
 * Copyright (c) 2014 Motorola Mobility
 * Copyright (c) 2014 Jaegeuk Kim <jaegeuk@kernel.org>
 */
#ifndef __NBFS_TRACE_H__
#define __NBFS_TRACE_H__

#ifdef CONFIG_NBFS_IO_TRACE
#include <trace/events/nbfs.h>

enum file_type {
	__NORMAL_FILE,
	__DIR_FILE,
	__NODE_FILE,
	__META_FILE,
	__ATOMIC_FILE,
	__VOLATILE_FILE,
	__MISC_FILE,
};

struct last_io_info {
	int major, minor;
	pid_t pid;
	enum file_type type;
	struct nbfs_io_info fio;
	block_t len;
};

extern void nbfs_trace_pid(struct page *);
extern void nbfs_trace_ios(struct nbfs_io_info *, int);
extern void nbfs_build_trace_ios(void);
extern void nbfs_destroy_trace_ios(void);
#else
#define nbfs_trace_pid(p)
#define nbfs_trace_ios(i, n)
#define nbfs_build_trace_ios()
#define nbfs_destroy_trace_ios()

#endif
#endif /* __NBFS_TRACE_H__ */
