#ifndef _LINUX_QBLK_GLOBAL_H
#define _LINUX_QBLK_GLOBAL_H

#include <linux/types.h>

#define QBLK_IOCTL_RSV_SPACE (0x9618)
#define QBLK_IOCTL_GETGEO (0x9619)

struct qblk_geo {
	int num_ch;
	int num_lun;
	int num_lines;
	int num_plane;
	int clba;
	int flashpage_size; /* in Bytes*/
	int num_pages_in_block;
	int oobsize;
};

/* This structure is allocated/deallocated by fs */
struct qblk_reserve_space_context {
	unsigned long reserve_start;
	atomic_t finished;
	int return_status;
};


#endif  /* _LINUX_AOFS_FS_H */
