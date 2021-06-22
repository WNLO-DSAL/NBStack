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
#include <linux/qblk.h>

#include "nbfs.h"
#include "node.h"
#include "segment.h"
#include "xattr.h"
#include "gc.h"
#include "trace.h"

#include <trace/events/nbfs.h>

struct nbfs_sb_info *nbfs_debug_sbi;

#ifdef MONITOR_TIME
void inline nbfs_printTimeMonotonic(const char *ch, int line)
{
	struct timespec ts;

	getrawmonotonic(&ts);
	pr_notice("%s line %d s %ld ns %ld\n",
					ch,
					line,
					ts.tv_sec,
					ts.tv_nsec);
}
#else
void inline nbfs_printTimeMonotonic(const char *ch, int line)
{
}
#endif

void nbfs_printBioStatus (struct bio *bio)
{
	int i;
	unsigned long *p;
	if(!bio){
		pr_notice("===printBioStatus===bio==NULL\n");
		return;
	}
	pr_notice("----------printBioStatus----------------\n");
	pr_notice("bi_opf=0x%x,__bi_cnt=%d,status=0x%x,vcnt=%d\n",bio->bi_opf,atomic_read(&bio->__bi_cnt),bio->bi_status,(int)bio->bi_vcnt);
							
	pr_notice("iter.sector=%lu,size=%u,idx=%u,vecdone=%u\n",
		bio->bi_iter.bi_sector,bio->bi_iter.bi_size,bio->bi_iter.bi_idx,
		bio->bi_iter.bi_bvec_done);
								
	for(i=0;i<bio->bi_vcnt;i++){
		p = (unsigned long *)page_address(bio->bi_io_vec[i].bv_page);
		pr_notice("page=%p,p=0x%lx,len=0x%x,offset=0x%x\n",
										page_address(bio->bi_io_vec[i].bv_page),
										(unsigned long)p,
										bio->bi_io_vec[i].bv_len,
										bio->bi_io_vec[i].bv_offset);
									//pr_notice("data=%lx %lx %lx %lx\n",p[0],p[1],p[2],p[3]);
	}
								
	pr_notice("----------EndOf{PrintBioStatus}----------------\n");
							
}

void nbfs_print_node_info(struct page *page)
{
	struct nbfs_node *rn = NBFS_NODE(page);

	pr_notice("---%s----\n", __func__);
	pr_notice("cpver(%llu) flag(0x%x) ino(%u) nextblkaddr(%u) nid(%u)\n",
				le64_to_cpu(rn->footer.cp_ver),
				le32_to_cpu(rn->footer.flag),
				le32_to_cpu(rn->footer.ino),
				le32_to_cpu(rn->footer.next_blkaddr),
				le32_to_cpu(rn->footer.nid)
				);
	pr_notice("==========\n");
}


static void nbfs_test_rsv(char *cmd)
{
	struct block_device *bdev = nbfs_debug_sbi->sb->s_bdev;
	struct qblk_reserve_space_context ctx;

	atomic_set(&ctx.finished, 0);
	ctx.reserve_start = MAIN_BLKADDR(nbfs_debug_sbi);
	barrier();
	blkdev_ioctl(bdev, 0, QBLK_IOCTL_RSV_SPACE, (unsigned long)&ctx);
	while(!atomic_read(&ctx.finished))
		schedule();
	pr_notice("%s, done\n",__func__);
}

static void nbfs_test_getgeo(char *cmd)
{
	struct block_device *bdev = nbfs_debug_sbi->sb->s_bdev;
	struct qblk_geo geo;

	blkdev_ioctl(bdev, 0, QBLK_IOCTL_GETGEO, (unsigned long)&geo);
	pr_notice("%s, ch[%d] lines[%d]\n",
			__func__, geo.num_ch, geo.num_lines);
}

static void nbfs_testoobwrite_endio(struct bio *bio)
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

		end_page_writeback(page);
	}


	bio_put(bio);
}


//o @addr1 @oob1 @addr2 @oob2 ...
static void nbfs_test_oobwrite(char *cmd)
{
	struct bio *bio;
	unsigned long addr, oob;
	int i;
	int total;
	static struct page *pages[64];
	static unsigned long oobs[64];
	unsigned long baseaddr = 0;
	char *inp;
	int ret;

	inp = cmd;
	for (i = 0;;i++) {
		ret = sscanf(inp, "%lu %lu", &addr, &oob);
		pr_notice("addr %lu oob %lu ret %d\n", addr, oob, ret);
		if (!addr)
			break;
		if (!i)
			baseaddr = addr;
		while (*inp++ != ' ');
		while (*inp++ != ' ');
		
	}
	total = i;

	bio = bio_alloc(GFP_KERNEL, total);
	//bio = bio_alloc_withmeta(GFP_KERNEL, total, total);
	nbfs_target_device(nbfs_debug_sbi, baseaddr, bio);
	bio->bi_end_io = nbfs_testoobwrite_endio;
	bio->bi_private = nbfs_debug_sbi;
	inp = cmd;
	for (i = 0; i < total; i++) {

		sscanf(inp, "%lu %lu", &addr, &oobs[i]);
		while (*inp++ != ' ');
		while (*inp++ != ' ');

		pages[i] = alloc_page(GFP_KERNEL);

		bio_add_page(bio, pages[i], PAGE_SIZE, 0);
		//bio_add_page_with_meta(bio, pages[i], PAGE_SIZE, 0, &oobs[i]);
	}

	submit_bio(bio);

	//for (i = 0; i < total; i++) {
	//	wait_on_page_writeback(pages[i]);
	//	__free_page(pages[i]);
	//}
}


static ssize_t nbfsDebug_write(struct file *file,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	char usrCommand[512];
	int ret;

	ret = copy_from_user(usrCommand, buffer,count);
	//pr_notice("command:%s",usrCommand);
	switch (usrCommand[0]) {
	case 't':
		pr_notice("%s, t\n", __func__);
		nbfs_test_rsv(&usrCommand[1]);
		break;
	case 'g':
		pr_notice("%s, g\n", __func__);
		nbfs_test_getgeo(&usrCommand[1]);
		break;
	case 'o':
		pr_notice("%s, o\n", __func__);
		nbfs_test_oobwrite(&usrCommand[2]);
		break;
	}
	return count;
}


static const struct file_operations nbfsDebug_proc_fops = {
  .owner = THIS_MODULE,
  .write = nbfsDebug_write,
};

void nbfs_debug_init(void *private, int mark)
{
	char buf[30];

	nbfs_debug_sbi = private;
	sprintf(buf, "nbfsDebug%d", mark);
	proc_create(buf, 0, NULL, &nbfsDebug_proc_fops);

}

void nbfs_debug_exit(int mark)
{
	char buf[30];

	sprintf(buf, "nbfsDebug%d", mark);
	remove_proc_entry(buf, NULL);
}

