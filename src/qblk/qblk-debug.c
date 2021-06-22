#include "qblk.h"
#define DEBUGCHNLS (2)

#define TEST_SECS_PER_REQ (8)
#define TEST_SECS_ORDER_PER_REQ (3)

static struct qblk *debugqblk;

struct qblk_debug_endreq_struct {
	struct request_queue *q;
	int rw;
	struct hd_struct *part;
	unsigned long start_time;
	struct request *rq;
	blk_status_t error;
	struct qblk *qblk;
};

int endreq_array_head, endreq_array_tail;
struct qblk_debug_endreq_struct endreq_array[32];

static char ls_name[30][30] = {"TYPE_FREE",
								"TYPE_LOG",
								"TYPE_DATA",
								"",
								"",
								"",
								"",
								"",
								"",
								"NEW",
								"FREE",
								"OPEN",
								"CLOSED",
								"GC",
								"BAD",
								"CORRUPT",
								"",
								"",
								"",
								"",
								"GC_NONE",
								"GC_EMPTY",
								"GC_LOW",
								"GC_MID",
								"GC_HIGH",
								"GC_FULL"
								};

void qblk_printBioStatus (struct bio *bio){
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

void printRqdStatus(struct nvm_rq *rqd)
{
	int i;
	struct ppa_addr *p_ppa;
	struct qblk_c_ctx *c_ctx;

	c_ctx = nvm_rq_to_pdu(rqd);

	pr_notice("---------%s-------\n", __func__);

	pr_notice("c_ctx{sentry[%u]nr_valid[%u]npad[%u]ch[%u]rb[%u]}\n",
				c_ctx->sentry, c_ctx->nr_valid,
				c_ctx->nr_padded, c_ctx->ch_index,
				c_ctx->rb_count);

	pr_notice("opcode[%d] nr_ppas[%u] \n",
				rqd->opcode, rqd->nr_ppas);
	if (rqd->nr_ppas == 1) {
		pr_notice("ppa[%llx]\n", rqd->ppa_addr.ppa);
		pr_notice("ppa: :ch:%d,lun:%d,blk:%d,pg:%d,pl:%d,sec:%d\n",
			rqd->ppa_addr.g.ch, rqd->ppa_addr.g.lun, rqd->ppa_addr.g.blk,
			rqd->ppa_addr.g.pg, rqd->ppa_addr.g.pl, rqd->ppa_addr.g.sec);
	}
	else {
		p_ppa = rqd->ppa_list;
		for (i = 0; i < rqd->nr_ppas; i++) {
			pr_notice("ppa[%llx]\n", p_ppa->ppa);
			pr_notice("ppa: :ch:%d,lun:%d,blk:%d,pg:%d,pl:%d,sec:%d\n",
				p_ppa->g.ch, p_ppa->g.lun, p_ppa->g.blk,
				p_ppa->g.pg, p_ppa->g.pl, p_ppa->g.sec);
			p_ppa++;
		}
	}

	qblk_printBioStatus(rqd->bio);
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}


void printBufSample(void *data)
{
	int i;
	unsigned long long *p = data;

	pr_notice("---------%s-------\n", __func__);
	for (i = 0; i < 16; i++) {
		pr_notice("0x%llx\n", *p);
		p++;
	}
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}

void print_gcrq_status(struct qblk_gc_rq *gc_rq)
{
	int nsec = gc_rq->nr_secs;
	int i;

	pr_notice("---------%s-------\n", __func__);
	pr_notice("ch[%d], line[%u], nrsecs[%d], secstogc[%d]\n",
				gc_rq->chi->ch_index, gc_rq->line->id,
				gc_rq->nr_secs,
				gc_rq->secs_to_gc);
	for (i = 0; i < nsec; i++) {
		pr_notice("lba[0x%llx], ppa[0x%llx]\n",
						gc_rq->lba_list[i],
						gc_rq->paddr_list[i]);
	}
	
	pr_notice("<<<<<<%s>>>>>>\n", __func__);
}

/*-------------------------------printDebug------------------------------*/

static void qblk_print_debugentry(struct qblk_debug_entry *entry, int index)
{
	struct timeval *time1 = &entry->time;
	struct timeval *time2 = &entry->time2;
	struct timeval *time3 = &entry->time3;

	pr_notice("type=%d=TS=%ld=ppa=%x=%x=%x=%x=%x=%x=NS=%d=ts1=%ld=tus1=%ld=ts2=%ld=tus2=%ld=ts3=%ld=tus3=%ld\n",
		entry->type,
		1000000 * (time2->tv_sec-time1->tv_sec) +
			time2->tv_usec - time1->tv_usec,
		entry->firstppa.g.ch, entry->firstppa.g.lun,
		entry->firstppa.g.pl, entry->firstppa.g.sec,
		entry->firstppa.g.pg, entry->firstppa.g.blk,
		entry->nr_secs,
		time1->tv_sec, time1->tv_usec,
		time2->tv_sec, time2->tv_usec,
		time3->tv_sec, time3->tv_usec
		);
}

static void qblk_print_debug(struct qblk *qblk,
			int chnl, int irqsave)
{
	struct qblk_debug_header *header =
					&qblk->debugHeaders[chnl];
	unsigned long flags;
	int i;
	int end;

	if (chnl >= DEBUGCHNLS)
		return;

	if (irqsave)
		spin_lock_irqsave(&qblk->debug_printing_lock, flags);
	else
		spin_lock(&qblk->debug_printing_lock);
	spin_lock(&header->lock);
	end = header->p;
	pr_notice("------------print logs of ch[%d]---------------\n", chnl);
	for (i = 0; i < end; i++)
		qblk_print_debugentry(&header->entries[i], i);
	pr_notice("============print logs of ch[%d]===============\n", chnl);
	spin_unlock(&header->lock);
	if (irqsave)
		spin_unlock_irqrestore(&qblk->debug_printing_lock, flags);
	else
		spin_unlock(&qblk->debug_printing_lock);
}


/*-------------------------------IOtest------------------------------*/

static void qblk_end_test_ioerase(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;

	mempool_free(rqd, qblk->e_rq_pool);
	atomic_dec(&qblk->inflight_io);
}


int qblk_blk_erase_test_async(struct qblk *qblk, struct ppa_addr ppa)
{
	struct nvm_rq *rqd;
	int err;

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_ERASE);
	if (!rqd)
		return -ENOMEM;

	rqd->opcode = NVM_OP_ERASE;
	rqd->ppa_addr = ppa;
	rqd->nr_ppas = 1;
	rqd->flags = qblk_set_progr_mode(qblk, QBLK_ERASE);
	rqd->bio = NULL;

	rqd->end_io = qblk_end_test_ioerase;
	rqd->private = qblk;

	/* The write thread schedules erases so that it minimizes disturbances
	 * with writes. Thus, there is no need to take the LUN semaphore.
	 */
	err = qblk_submit_io(qblk, rqd);
	if (err)
		pr_err("qblk: could not async erase line:%d,ppa:0x%llx\n",
					qblk_ppa_to_line(ppa),
					ppa.ppa);

	return err;
}

/*-------------------------------debugA------------------------------*/
static noinline void debugA(int a, int b, int c, spinlock_t *lock)
{
	int d = 5;

	a = 1;
	spin_lock(lock);
	b = 2;
	spin_unlock(lock);
	c = d;
}

/* usage: "e @chnl @lun @pl @blk @page @sector"*/
static void qblk_test_erase(struct qblk *qblk,char *usrCommand)
{
	struct ppa_addr ppa;
	int ch, lun, pl, blk, pg, sec;
	sscanf(usrCommand, "%d %d %d %d %d %d", &ch, &lun,
					&pl, &blk, &pg, &sec);
	ppa.g.ch = ch;
	ppa.g.lun =lun;
	ppa.g.pl = pl;
	ppa.g.blk = blk;
	ppa.g.pg = pg;
	ppa.g.sec = sec;
	pr_notice("%s, ppa = 0x%llx\n",
						__func__, ppa.ppa);

	qblk_blk_erase_test_async(qblk, ppa);
	return;
}


static void __print_line_info(struct qblk *qblk,
					int ch_idx, int line_id)
{
	struct ch_info *chi = &qblk->ch[ch_idx];
	struct qblk_line *line = &chi->lines[line_id];

	pr_notice("----%s,ch[%d] line[%d]-----\n",
						__func__, ch_idx, line_id);

	pr_notice("left_eblks(Blocks left for erasing)=%u\n", atomic_read(&line->left_eblks));
	pr_notice("left_seblks(Blocks left for sync erasing)=%u\n", atomic_read(&line->left_seblks));
	pr_notice("left_msecs(Sectors left for mapping)=%d\n", line->left_msecs);
	pr_notice("ref=%u\n", kref_read(&line->ref));
	pr_notice("vsc=%d\n", qblk_line_vsc(line));
	pr_notice("nr_valid_lbas=%u\n", line->nr_valid_lbas);
	pr_notice("smetaSsec[%llu] emetaSsec[%llu]\n",
				line->smeta_ssec, line->emeta_ssec);
	pr_notice("lineState=%s(%d)\n", ls_name[line->state],line->state);
	pr_notice("lineRef[%d]\n", kref_read(&line->ref));
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "l @chnl @lineID"*/
static void qblk_printLineInfo(struct qblk *qblk, char *usrCommand)
{
	int ch_idx, line_id;

	sscanf(usrCommand, "%d %d", &ch_idx, &line_id);
	__print_line_info(qblk, ch_idx, line_id);
}

static void __print_rl_info(struct qblk *qblk, int chnl)
{
	struct qblk_per_chnl_rl *rl = &qblk->ch[chnl].per_ch_rl;
	unsigned long flags;

	pr_notice("----%s,ch[%d]-----\n",
						__func__, chnl);

	pr_notice("veryHigh[%u] high[%u] mid[%u] rsv[%u]\n",
			rl->very_high, rl->high, rl->mid_blocks, rl->rsv_blocks);
	pr_notice("free_blks[%u] free_usrBlks[%u]\n",
			atomic_read(&rl->free_blocks), atomic_read(&rl->free_user_blocks));
	pr_notice("rb_gc_max[%u] chnl_state[%d](high1 mid2 low3)\n",
			atomic_read(&rl->rb_gc_max), rl->chnl_state);
	spin_lock_irqsave(&rl->remain_secs_lock, flags);
	pr_notice("remain_secs=%u\n", rl->remain_secs);
	pr_notice("total written sectors=%llu\n",
			atomic64_read(&rl->written_sectors));
	spin_unlock_irqrestore(&rl->remain_secs_lock, flags);
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "r @chnl"*/
static void qblk_printRlInfo(struct qblk *qblk, char *usrCommand)
{
	int ch_idx;

	sscanf(usrCommand, "%d", &ch_idx);
	__print_rl_info(qblk, ch_idx);
}

static void __print_gc_info(struct qblk *qblk, int ch_idx)
{
	struct qblk_gc *gc = &qblk->per_channel_gc[ch_idx];
	struct ch_info *chi = &qblk->ch[ch_idx];
	struct list_head *group_list;
	int gc_group;
	struct qblk_line *line;

	pr_notice("----%s,ch[%d]-----\n",
						__func__, ch_idx);
	pr_notice("gc->gc_enabled[%d]\n",
			atomic_read(&gc->gc_enabled)
			);
	for (gc_group = 0;
			gc_group < QBLK_GC_NR_LISTS;
			gc_group++) {
		group_list = chi->gc_lists[gc_group];
		if(list_empty(group_list)) {
			pr_notice("grouplist[%d] empty\n", gc_group);
			continue;
		}
		pr_notice("grouplist[%d] {\n", gc_group);
		list_for_each_entry(line, group_list, list) {
			pr_notice("<%u>\n", line->id);
		}
		pr_notice("}\n");
	}
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "c @chnl"*/
static void qblk_printGcInfo(struct qblk *qblk,char *usrCommand)
{
	int ch_idx;

	sscanf(usrCommand, "%d", &ch_idx);
	__print_gc_info(qblk, ch_idx);
}

/* usage: "d @rb_index @nr_dummies"*/
static void qblk_testdummy(struct qblk *qblk, char *usrCommand)
{
	int rb_idx, ndummy;
	struct qblk_rb *rb;
	int mem;
	int i;
	int pos;
	struct qblk_rb_entry *entry;

	sscanf(usrCommand, "%d%d", &rb_idx, &ndummy);
	rb = &qblk->mqrwb[rb_idx];
	spin_lock(&rb->w_lock);
	mem = READ_ONCE(rb->mem);
	for (i = 0; i < ndummy; i++) {
		int flags;

		pos = qblk_rb_wrap_pos(rb, mem + i);
		entry = &rb->entries[pos];
		entry->w_ctx.lba = entry->w_ctx.ppa.ppa = ADDR_EMPTY;
		flags = READ_ONCE(entry->w_ctx.flags) | QBLK_WRITTEN_DATA;
		smp_store_release(&entry->w_ctx.flags, flags);
	}
	pos = qblk_rb_wrap_pos(rb, mem + i);
	smp_store_release(&rb->mem, pos);
	spin_unlock(&rb->w_lock);
}


/* usage: "g"*/
static void qblk_printGlobalRlInfo(struct qblk *qblk,char *usrCommand)
{
	struct qblk_rl *rl = &qblk->rl;

	pr_notice("----%s-----\n",
						__func__);

	pr_notice("nrsecs=%llu, total_blocks=%lu\n",
						rl->nr_secs,
						rl->total_blocks);
	pr_notice("per_chnl_limit=%d,rb_user_active=%d\n",
							rl->per_chnl_limit,
							rl->rb_user_active
							);
	pr_notice("rb_user_max=%d, rb_user_cnt=%d\n",
							atomic_read(&rl->rb_user_max),
							atomic_read(&rl->rb_user_cnt)
							);
	pr_notice("rb_gc_cnt=%d, rb_space=%d\n",
								atomic_read(&rl->rb_gc_cnt),
								atomic_read(&rl->rb_space)
							);
	pr_notice("gc_active=0x%lx\n", *qblk->gc_active);
	pr_notice("totalSubmitted=%u totalFinished=%u\n",
				atomic_read(&qblk->total_submitted),
				atomic_read(&qblk->total_finished));
	pr_notice("totalSubmitted2=%u totalFinished2=%u\n",
				atomic_read(&qblk->total_submitted2),
				atomic_read(&qblk->total_finished2));
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>>>>\n", __func__);
}

/* usage: "m @lpn"*/
static void qblk_printMap(struct qblk *qblk,char *usrCommand)
{
	int lpn;
	struct ppa_addr ppa;

	sscanf(usrCommand, "%d", &lpn);

	ppa = qblk_trans_map_atomic_get(qblk, lpn);

	pr_notice("%s:lpn[%d],ppn[0x%llx]\n",
						__func__, lpn, ppa.ppa);

}

static void __print_rb_info(struct qblk *qblk, int rb_idx)
{
	struct qblk_rb *rb = &qblk->mqrwb[rb_idx];

	printRbStatus(rb, rb_idx);
}

/* usage: "b @rb_index"*/
static void qblk_printRbInfo(struct qblk *qblk, char *usrCommand)
{
	int rb_idx;

	sscanf(usrCommand, "%d", &rb_idx);
	__print_rb_info(qblk, rb_idx);
	
}

/* usage: "w @rb_index @pos"*/
static void qblk_printWctxInfo(struct qblk *qblk, char *usrCommand)
{
	int rb_idx;
	int pos;
	struct qblk_rb *rb;
	struct qblk_w_ctx *wctx;

	sscanf(usrCommand, "%d %d", &rb_idx, &pos);
	rb = &qblk->mqrwb[rb_idx];
	wctx = qblk_rb_w_ctx(rb, pos);

	
}


/* usage: "q"*/
static void qblk_printMultiqueue_status(struct qblk *qblk)
{
	struct request_queue *queue = qblk->q;

	pr_notice("----%s  multiqueue_info-----\n", __func__);
	pr_notice("maxSeg=%u\n", queue_max_segments(queue));
}


/* usage: "s"*/
static void qblk_printSInfo(struct qblk *qblk,char *usrCommand)
{
	int nr_chnl = qblk->nr_channels;
	int nr_rb = qblk->nr_queues;
	int i, j;
	struct ch_info *chi;
	long totalvsc, chnlvsc;

	pr_notice("----%s  rbinfo-----\n", __func__);
	pr_notice("*************************************\n");
	for (i=0;i<nr_rb;i++)
		__print_rb_info(qblk, i);
	pr_notice("----%s  global rl-----\n", __func__);
	pr_notice("*************************************\n");
	qblk_printGlobalRlInfo(qblk, usrCommand);
	pr_notice("----%s  per_ch rl+gc+line-----\n", __func__);
	pr_notice("*************************************\n");
	totalvsc = 0;
	for (i = 0;i < nr_chnl; i++) {
		pr_notice("((((((((((chnl[%d]((((((((\n", i);
		chi = &qblk->ch[i];
		pr_notice("dataline=%u, datanext=%u\n",
							chi->data_line->id,
							chi->data_next->id);
		__print_rl_info(qblk, i);
		__print_gc_info(qblk, i);
		chnlvsc = 0;
		for (j = 0; j < chi->nr_lines; j++) {
			struct qblk_line *line = &chi->lines[j];
			int vsc;
			
			__print_line_info(qblk, i, j);
			vsc = qblk_line_vsc(line);
			if (vsc > 0) {
				chnlvsc += vsc;
				totalvsc += vsc;
			}
		}
		pr_notice(")))))chnl[%d] chnlvsc[%ld])))\n", i, chnlvsc);
	}
	pr_notice("<<<<<<<<<<<<%s>>totalvsc[%ld]>>>>>>>\n",
					__func__, totalvsc);
}

/* usage: "x 1/0"*/
static void qblk_alterPrintRqOption(struct qblk *qblk,char *usrCommand)
{
	int newps;

	sscanf(usrCommand, "%d", &newps);

	qblk->print_rq_status = newps;
	return;
}

/* usage: "z"*/
static void qblk_printGeoInfo(struct qblk *qblk,char *usrCommand)
{
	struct nvm_geo *geo = &qblk->dev->geo;


	pr_notice("--------%s-----\n",
							__func__);
	//pr_notice("max_rq_size[%d]\n", geo->max_rq_size);
	pr_notice("num_ch[%d] all_luns[%d] num_lun[%d] num_chk[%d]\n",
							geo->num_ch,
							geo->all_luns,
							geo->num_lun,
							geo->num_chk);
	pr_notice("ppaf:\n");
#if 0
	pr_notice("blk_len[%d] blk_offset[%d] ch_len[%d] ch_offset[%d]\n",
		geo->addrf.blk_len,
		geo->addrf.blk_offset,
		geo->addrf.ch_len,
		geo->addrf.ch_offset);
	pr_notice("lun_len[%d] lun_offset[%d] pg_len[%d] pg_offset[%d]\n",
		geo->addrf.lun_len,
		geo->addrf.lun_offset,
		geo->addrf.pg_len,
		geo->addrf.pg_offset);
	pr_notice("pln_len[%d] pln_offset[%d] sect_len[%d] sect_offset[%d]\n",
		geo->addrf.pln_len,
		geo->addrf.pln_offset,
		geo->addrf.sect_len,
		geo->addrf.sect_offset);
#endif
	pr_notice("<<<<<<<<<<<<%s>>>>>>>>>\n",
							__func__);
}

void qblk_debug_printBioStatus(struct bio *bio) {
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

//TODO: Add concurrency protection. Check whether the queue is full.
void qblk_debug_add_endreq(struct request_queue *q,
									int rw,
									struct hd_struct *part,
									unsigned long start_time,
									struct request *rq,
									blk_status_t error,
									struct qblk *qblk)
{
	endreq_array[endreq_array_tail].q = q;
	endreq_array[endreq_array_tail].rw = rw;
	endreq_array[endreq_array_tail].part = part;
	endreq_array[endreq_array_tail].start_time = start_time;
	endreq_array[endreq_array_tail].rq = rq;
	endreq_array[endreq_array_tail].error = error;
	endreq_array[endreq_array_tail].qblk = qblk;
	endreq_array_tail++;
	if (endreq_array_tail == 32)
		endreq_array_tail = 0;
}

#ifdef MONITOR_WRITE_AMPLIFICATION
static void qblk_print_wa(struct qblk *qblk)
{
	pr_notice("%s, smeta %u, emeta %u, nr_valid %u, nr_padded %u, nr_erase %u\n",
				__func__, atomic_read(&qblk->nsm),
				atomic_read(&qblk->nem),
				atomic_read(&qblk->nv),
				atomic_read(&qblk->np),
				atomic_read(&qblk->ner));
}

static void qblk_clear_wa(struct qblk *qblk)
{
	atomic_set(&qblk->nsm, 0);
	atomic_set(&qblk->nem, 0);
	atomic_set(&qblk->nv, 0);
	atomic_set(&qblk->np, 0);
	atomic_set(&qblk->ner, 0);
}
#endif

static ssize_t qblkDebug_write(struct file *file,
				const char __user *buffer,
				size_t count, loff_t *ppos)
{
	char usrCommand[512];
	int ret;
	int i;
	struct qblk *qblk = debugqblk;
	spinlock_t testlock;

	ret = copy_from_user(usrCommand, buffer,count);
	//pr_notice("command:%s",usrCommand);
	switch (usrCommand[0]) {
	case 'a':
		spin_lock_init(&testlock);
		pr_notice("%s, a\n", __func__);
		debugA(9,8,7,&testlock);
		break;
	case 'b':
		pr_notice("%s, b\n", __func__);
		qblk_printRbInfo(qblk, &usrCommand[1]);
		break;
	case 'c':
		pr_notice("%s, c\n", __func__);
		qblk_printGcInfo(qblk, &usrCommand[1]);
		break;
	case 'd':
		pr_notice("%s, d\n", __func__);
		qblk_testdummy(qblk, &usrCommand[1]);
		break;
	case 'e':
		qblk_test_erase(qblk, &usrCommand[1]);
		break;
	case 'g':
		pr_notice("%s, g\n", __func__);
		qblk_printGlobalRlInfo(qblk, &usrCommand[1]);
		break;
#ifdef QBLK_COUNT_RB_REQ
	case 'i':
		pr_notice("%s, i\n", __func__);
		if (usrCommand[1] == 's') {
			int k;

			qblk->rb_need_count = 0;
			for (k = 0; k < 32; k++) {
				pr_notice("rb[%d]:%llu\n",
							k, qblk->rb_req_count[k]);
				qblk->rb_req_count[k] = 0;
			}
		} else if (usrCommand[1] == 'g') {
			qblk->rb_need_count = 1;
		}
		break;
#endif

	case 'p':
		pr_notice("%s, p\n", __func__);
		for (i = 0; i < DEBUGCHNLS; i++)
			qblk_print_debug(qblk, i, 1);
		break;
	case 'q':
		pr_notice("%s, q\n", __func__);
		qblk_printMultiqueue_status(qblk);
		break;
	case 'm':
		pr_notice("%s, m\n", __func__);
		qblk_printMap(qblk, &usrCommand[1]);
		break;
	case 'l':
		pr_notice("%s, l\n", __func__);
		qblk_printLineInfo(qblk, &usrCommand[1]);
		break;
	case 'r':
		pr_notice("%s, r\n", __func__);
		qblk_printRlInfo(qblk, &usrCommand[1]);
		break;
	case 's':
		pr_notice("%s, s\n", __func__);
		qblk_printSInfo(qblk, &usrCommand[1]);
		break;
	case 'w':
		pr_notice("%s, w\n", __func__);
		qblk_printWctxInfo(qblk, &usrCommand[1]);
		break;
	case 'x':
		pr_notice("%s, x\n", __func__);
		qblk_alterPrintRqOption(qblk, &usrCommand[1]);
		break;
#ifdef MONITOR_WRITE_AMPLIFICATION
	case 'y':
		if (usrCommand[1] == 'c')
			qblk_clear_wa(qblk);
		else
			qblk_print_wa(qblk);
		break;
#endif
	case 'z':
		pr_notice("%s, z\n", __func__);
		qblk_printGeoInfo(qblk, &usrCommand[1]);
		break;
	}
	return count;
}


static const struct file_operations qblkDebug_proc_fops = {
  .owner = THIS_MODULE,
  .write = qblkDebug_write,
};

int qblk_debug_init(struct qblk *qblk)
{
	int i;
	struct qblk_debug_header *header;

	debugqblk = qblk;
	endreq_array_head = endreq_array_tail = 0;
	qblk->debugHeaders = kmalloc_array(DEBUGCHNLS,
			sizeof(*qblk->debugHeaders), GFP_KERNEL);
	if (!qblk->debugHeaders)
		return -ENOMEM;
	for (i = 0; i < DEBUGCHNLS; i++) {
		header = &qblk->debugHeaders[i];
		spin_lock_init(&header->lock);
		header->p = 0;
	}
	spin_lock_init(&qblk->debug_printing_lock);
	proc_create("qblkDebug", 0, NULL, &qblkDebug_proc_fops);
	qblk->debugstart = 1;
	qblk->print_rq_status = 0;
#ifdef QBLK_COUNT_RB_REQ
	qblk->rb_need_count = 0;
	for (i = 0; i < 32; i++)
		qblk->rb_req_count[i] = 0;
#endif

#ifdef MONITOR_WRITE_AMPLIFICATION
	atomic_set(&qblk->nsm, 0);
	atomic_set(&qblk->nem, 0);
	atomic_set(&qblk->nv, 0);
	atomic_set(&qblk->np, 0);
	atomic_set(&qblk->ner, 0);
#endif
	return 0;
}

void qblk_debug_exit()
{
	remove_proc_entry("qblkDebug", NULL);
	WARN_ON(!debugqblk);
	if (debugqblk)
		kfree(debugqblk->debugHeaders);
}

#ifdef QBLK_TRACE_RB_CHANGE
void qblk_trace_rbChange(int rb_index, int isshrink, int changeValue)
{
	static int buflen[32];
	static int firstrun = 1;

	if (firstrun) {
		int i;

		firstrun = 0;
		for (i = 0; i < 32; i++)
			buflen[i] = 224;
	}

	if (!changeValue)
		return;
	if (isshrink)
		changeValue = 0 - changeValue;

	buflen[rb_index] += changeValue;
	pr_notice("%s %d %d %d %lu %d %d\n",
		__func__, rb_index, changeValue,
		buflen[rb_index] - changeValue,
		jiffies, 1, isshrink);
	pr_notice("%s %d %d %d %lu %d %d\n",
		__func__, rb_index, changeValue,
		buflen[rb_index],
		jiffies, 2, isshrink);
}
#endif


#ifdef MONITOR_TIME
void inline qblk_printTimeMonotonic(const char *ch, int line)
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
void inline qblk_printTimeMonotonic(const char *ch, int line)
{
}
#endif


#ifdef MONITOR_WRITE_AMPLIFICATION

/*
 * en: need to calculate
 * nsm: number of 4KiB pages for smeta
 * nem: number of 4KiB pages for emeta
 * nv: number of 4KiB pages for valid writeback
 * np: number of 4KiB pages for padded writeback
 * ner: number of chunk erase
 */
void qblk_debug_calc_wa(struct qblk *qblk, int en, int nsm, int nem, int nv, int np, int ner)
{
	if (en) {
		if (nsm)
			atomic_add(nsm, &qblk->nsm);
		if (nem)
			atomic_add(nem, &qblk->nem);
		if (nv)
			atomic_add(nv, &qblk->nv);
		if (np)
			atomic_add(np, &qblk->np);
		if (ner)
			atomic_add(ner, &qblk->ner);	
	}
}

#endif

