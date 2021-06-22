#include "qblk.h"

/* Finish persist work on rb.
 * Free persist_work
 */
void qblk_end_persist_point(struct qblk_rb *rb,
							struct qblk *qblk,
							struct qblk_persist_work *persist_work)
{
	int nr_rb = qblk->nr_queues;
	unsigned int rb_index = rb->rb_index;

	lockdep_assert_held(&rb->s_lock);

	spin_lock(&persist_work->lock);
	set_bit(rb_index, persist_work->persist_bm);
	//pr_notice("%s, rb[%d]\n", __func__, rb_index);

	if (find_first_zero_bit(persist_work->persist_bm, nr_rb) == nr_rb) {
		struct request *req = persist_work->req;

		spin_unlock(&persist_work->lock);
		blk_mq_end_request(req, BLK_STS_OK);
		qblk_printTimeMonotonic(__func__, __LINE__);
		qblk_persist_work_release(persist_work);
	} else {
		spin_unlock(&persist_work->lock);
	}

}


static inline void qblk_finish_PREFLUSH_FUA_in_rb(struct qblk *qblk,
					struct qblk_w_ctx *w_ctx,
					struct qblk_rb *rb,
					int pos)
{
	struct request *req = w_ctx->fua_req;
	struct qblk_per_rb_pw *pw, *tmp;

	lockdep_assert_held(&rb->s_lock);

	list_for_each_entry_safe(pw, tmp, &w_ctx->persist_list, list) {
		list_del(&pw->list);
		qblk_end_persist_point(rb, qblk, pw->pw);
	}

	if (req) {
		generic_end_io_acct(req->q, WRITE, &qblk->disk->part0, jiffies);
		blk_mq_end_request(req, BLK_STS_OK);
		qblk_printTimeMonotonic(__func__, __LINE__);
		w_ctx->fua_req = NULL;
	}

}

static unsigned long qblk_end_w_bio(struct qblk *qblk,
				struct nvm_rq *rqd,
				struct qblk_c_ctx *c_ctx)
{
	struct qblk_rb *ringBuffer = &qblk->mqrwb[c_ctx->rb_count];
	unsigned long ret;
	int i;

	//pr_notice("%s\n", __func__);
	lockdep_assert_held(&ringBuffer->s_lock);

	for (i = 0; i < c_ctx->nr_valid; i++) {
		struct qblk_w_ctx *w_ctx;
		int pos = c_ctx->sentry + i;

		w_ctx = qblk_rb_w_ctx(ringBuffer, pos);

		qblk_finish_PREFLUSH_FUA_in_rb(qblk, w_ctx, ringBuffer, pos);
	}

	if (c_ctx->nr_padded)
		qblk_bio_free_pages(qblk, rqd->bio, c_ctx->nr_valid,
							c_ctx->nr_padded);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(rqd->nr_ppas, &qblk->sync_writes);
#endif

	ret = qblk_rb_sync_advance(ringBuffer, c_ctx->nr_valid);

	bio_put(rqd->bio);
	qblk_free_rqd(qblk, rqd, QBLK_WRITE);

	return ret;
}

static unsigned long qblk_end_queued_w_bio(struct qblk *qblk,
					   struct nvm_rq *rqd,
					   struct qblk_c_ctx *c_ctx)
{
	//pr_notice("%s\n",__func__);
	list_del(&c_ctx->list);
	return qblk_end_w_bio(qblk, rqd, c_ctx);
}
				   
static int qblk_calc_secs_to_sync(struct qblk *qblk,
				unsigned int secs_avail,
				unsigned int secs_to_flush)
{
	int secs_to_sync;

	secs_to_sync = qblk_calc_secs(qblk, secs_avail, secs_to_flush);

#ifdef CONFIG_NVM_DEBUG
	if ((!secs_to_sync && secs_to_flush)
			|| (secs_to_sync < 0)
			|| (secs_to_sync > secs_avail && !secs_to_flush)) {
		pr_err("qblk: bad sector calculation (a:%d,s:%d,f:%d)\n",
				secs_avail, secs_to_sync, secs_to_flush);
	}
#endif

	return secs_to_sync;
}


static struct ch_info *qblk_writeback_channel(struct qblk *qblk,
			struct qblk_queue *pq)
{
#if 1
	int nr_ch;

	spin_lock(&qblk->current_channel_lock);
	nr_ch = qblk->current_channel++;
	if (qblk->current_channel == qblk->nr_channels)
		qblk->current_channel = 0;
	spin_unlock(&qblk->current_channel_lock);
	return &qblk->ch[nr_ch];
#endif
	//return &qblk->ch[0];
#if 0
	int nr_ch;

	nr_ch = READ_ONCE(pq->wbchnl);
	if (nr_ch == qblk->nr_channels-1)
		WRITE_ONCE(pq->wbchnl, 0);
	else
		WRITE_ONCE(pq->wbchnl, nr_ch+1);
	return &qblk->ch[nr_ch];
#endif
}

static void qblk_complete_write(struct qblk *qblk,
			struct nvm_rq *rqd,
			struct qblk_c_ctx *c_ctx)
{
	struct qblk_c_ctx *c, *r;
	unsigned long flags;
	unsigned long pos;
	unsigned int rb_count = c_ctx->rb_count;
	struct ch_info *chi = &qblk->ch[c_ctx->ch_index];
	struct qblk_per_chnl_rl *pch_rl = &chi->per_ch_rl;
	unsigned int nr_valid;

	atomic64_add(rqd->nr_ppas, &pch_rl->written_sectors);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_sub(c_ctx->nr_valid, &qblk->inflight_writes);
#endif
	//pr_notice("%s,%d\n",__func__,__LINE__);

	if (rqd->nr_ppas == 1)
		qblk_up_rq(qblk, &rqd->ppa_addr, rqd->nr_ppas, c_ctx->lun_bitmap);
	else
		qblk_up_rq(qblk, rqd->ppa_list, rqd->nr_ppas, c_ctx->lun_bitmap);

	pos = qblk_rb_sync_init(&qblk->mqrwb[rb_count], &flags);
	BUG_ON(!c_ctx->nr_valid);
	nr_valid = c_ctx->nr_valid;
	if (pos == c_ctx->sentry) {
		//pr_notice("%s,pos==sentry==%lu\n",__func__,pos);
		pos = qblk_end_w_bio(qblk, rqd, c_ctx);

retry:
		list_for_each_entry_safe(c, r, &qblk->complete_list_mq[rb_count], list) {
			BUG_ON(c == c_ctx);
			rqd = nvm_rq_from_c_ctx(c);
			if (c->sentry == pos) {
				//pr_notice("%s,(queued)line=%d,pos==sentry==%lu\n",__func__,__LINE__,pos);
				pos = qblk_end_queued_w_bio(qblk, rqd, c);
				goto retry;
			}
		}
		//("%s,%d\n",__func__,__LINE__);
	} else {
		//pr_notice("%s,pos=%lu,sentry=%u\n",__func__,pos,c_ctx->sentry);
		WARN_ON(nvm_rq_from_c_ctx(c_ctx) != rqd);
		list_add_tail(&c_ctx->list, &qblk->complete_list_mq[rb_count]);
	}
	qblk_rb_sync_end(&qblk->mqrwb[rb_count], &flags);
	atomic_sub(nr_valid,
		&qblk->queues[rb_count].inflight_write_secs);
}

static void qblk_end_io_write(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		qblk_log_write_err(qblk, rqd);
		return;
	}
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(rqd->bio->bi_status, "qblk: corrupted write error\n");
#endif
	//qblk_debug_complete_time(qblk, c_ctx->logindex, c_ctx->ch_index);
	qblk_complete_write(qblk, rqd, c_ctx);
	//qblk_debug_complete_time3(qblk, c_ctx->logindex, c_ctx->ch_index);

	atomic_dec(&qblk->inflight_io);
	//pr_notice("%s:complete writeToDisk request\n", __func__);
}

static void qblk_end_io_write_meta(struct nvm_rq *rqd)
{
	struct qblk *qblk = rqd->private;
	struct qblk_g_ctx *m_ctx = nvm_rq_to_pdu(rqd);
	struct qblk_line *line = m_ctx->private;
	struct qblk_emeta *emeta = line->emeta;
	int sync;

	//pblk_up_page(pblk, rqd->ppa_list, rqd->nr_ppas);

	if (rqd->error) {
		qblk_log_write_err(qblk, rqd);
		pr_err("qblk: metadata I/O failed. Line %d\n", line->id);
	}

	sync = atomic_add_return(rqd->nr_ppas, &emeta->sync);
	//pr_notice("%s,ch=%d,line=%u,sync=%d\n",
	//		__func__, line->chi->ch_index, line->id, sync);
	if (sync == emeta->nr_entries) {
		qblk_gen_run_ws(qblk, line, NULL, qblk_line_close_ws,
						GFP_ATOMIC, qblk->close_wq);
	}

	qblk_free_rqd(qblk, rqd, QBLK_WRITE_INT);

	//qblk_debug_complete_time(qblk, m_ctx->logindex, line->chi->ch_index);

	atomic_dec(&qblk->inflight_io);
}

int qblk_alloc_w_rq(struct qblk *qblk,
				struct nvm_rq *rqd,
			   unsigned int nr_secs,
			   nvm_end_io_fn(*end_io))
{
	struct nvm_tgt_dev *dev = qblk->dev;

	/* Setup write request */
	rqd->opcode = NVM_OP_PWRITE;
	rqd->nr_ppas = nr_secs;
	rqd->flags = qblk_set_progr_mode(qblk, QBLK_WRITE);
	rqd->private = qblk;
	rqd->end_io = end_io;

	rqd->meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&rqd->dma_meta_list);
	if (!rqd->meta_list)
		return -ENOMEM;

	rqd->ppa_list = rqd->meta_list + qblk_dma_meta_size(qblk);
	rqd->dma_ppa_list = rqd->dma_meta_list + qblk_dma_meta_size(qblk);

	return 0;
}

static int qblk_setup_w_rq(struct qblk *qblk,
			struct nvm_rq *rqd,
			unsigned int qcount,
			struct ppa_addr *erase_ppa,
			struct ch_info **pchi)
{
	struct ch_info *chi;
	struct qblk_line *e_line;
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct qblk_metainfo *metainfo = &qblk->metainfo;
	unsigned int valid = c_ctx->nr_valid;
	unsigned int padded = c_ctx->nr_padded;
	unsigned int nr_secs = valid + padded;
	unsigned long *lun_bitmap;
	int ret;
	int retryCount = 0;
	struct qblk_queue *rb_queue = &qblk->queues[qcount];

#if 0
	if (qblk_has_reserved(qblk)) {
		/* If we've reserved some lbas,
		 * we need to take them into account.
		 */
	}
#endif

retryChi:
	chi =
		qblk_writeback_channel(qblk, rb_queue);

	if(qblk_channel_may_writeback(qblk, chi, valid)) {
		retryCount++;
		if (retryCount > QBLK_DRAIN_RETRY_THRESHOLD) {
			//pr_notice("%s, retry count too high, require[%u]\n",
			//		__func__, valid);
			retryCount = 0;
			schedule();
		}
		goto retryChi;
	}

	/*
	 * Now we've already acquired enough space budget in this channel.
	 * So, there is no need to change channel from now on.
	 */

	e_line = qblk_line_get_erase(chi);

	//pr_notice("%s, ch = %d\n",
	//		__func__, chi->ch_index);
	lun_bitmap = kzalloc(metainfo->lun_bitmap_len, GFP_KERNEL);
	if (!lun_bitmap)
		return -ENOMEM;
	c_ctx->lun_bitmap = lun_bitmap;
	c_ctx->rb_count = qcount;
	c_ctx->ch_index = chi->ch_index;
	ret = qblk_alloc_w_rq(qblk, rqd, nr_secs, qblk_end_io_write);
	if (ret) {
		kfree(lun_bitmap);
		return ret;
	}

	if (likely(!e_line || !atomic_read(&e_line->left_eblks)))
		qblk_map_rq(qblk, chi, rqd, c_ctx->sentry,
						lun_bitmap, valid, 0, qcount);
	else
		qblk_map_erase_rq(qblk, chi, rqd, c_ctx->sentry,
					lun_bitmap,	valid, erase_ppa, qcount);
	*pchi = chi;
	return 0;
}

//---
static inline bool qblk_valid_meta_ppa(struct qblk *qblk,
				       struct qblk_line *meta_line,
				       struct nvm_rq *data_rqd)
{
return true;
#if 0
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_c_ctx *data_c_ctx = nvm_rq_to_pdu(data_rqd);
	struct qblk_line *data_line = qblk_line_get_data(qblk);
	struct ppa_addr meta_ppa, ppa_opt;
	u64 offset_inchannel;
	int pos_opt;

	/* Schedule a metadata I/O that is half the distance from the data I/O
	 * with regards to the number of LUNs forming the pblk instance. This
	 * balances LUN conflicts across every I/O.
	 *
	 * When the LUN configuration changes (e.g., due to GC), this distance
	 * can align, which would result on metadata and data I/Os colliding. In
	 * this case, modify the distance to not be optimal, but move the
	 * optimal in the right direction.
	 */
	offset_inchannel = qblk_lookup_page(qblk, meta_line);

	meta_ppa.g.sec = offset_inchannel &

	meta_ppa = addr_to_gen_ppa(qblk, offset_inchannel, 0);

	ppa_opt = addr_to_gen_ppa(qblk, paddr + data_line->meta_distance, 0);
	pos_opt = qblk_ppa_to_pos(geo, ppa_opt);

	if (test_bit(pos_opt, data_c_ctx->lun_bitmap) ||
				test_bit(pos_opt, data_line->blk_bitmap))
		return true;

	if (unlikely(qblk_ppa_comp(ppa_opt, ppa)))
		data_line->meta_distance--;

	return false;
#endif
}

static struct qblk_line *qblk_should_submit_meta_io(struct qblk *qblk,
					struct nvm_rq *data_rqd, struct ch_info *chi)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_line *meta_line;

	spin_lock(&chi->close_lock);
retry:
	if (list_empty(&chi->emeta_list)) {
		spin_unlock(&chi->close_lock);
		return NULL;
	}

	meta_line = list_first_entry(&chi->emeta_list, struct qblk_line, list);
	if (meta_line->emeta->mem >= meta->emeta_len[0])
		goto retry;

	list_del(&meta_line->list);
	spin_unlock(&chi->close_lock);

	if (!qblk_valid_meta_ppa(qblk, meta_line, data_rqd)) {
		spin_lock(&chi->close_lock);
		list_add_tail(&meta_line->list, &chi->emeta_list);
		spin_unlock(&chi->close_lock);
		return NULL;
	}
	//pr_notice("%s,metaline=%u\n",__func__,meta_line->id);
	return meta_line;
}

int qblk_submit_meta_io(struct qblk *qblk,
			struct qblk_line *meta_line, struct ch_info *chi)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct qblk_emeta *emeta = meta_line->emeta;
	struct qblk_g_ctx *m_ctx;
	struct bio *bio;
	struct nvm_rq *rqd;
	void *data;
	struct ppa_addr newpage;
	int rq_ppas = qblk->min_write_pgs;
	int rq_len;
	int i, j;
	int ret;
	//struct qblk_log_entry logentry;

	//pr_notice("%s,ch[%d],line[%u]\n",
	//			__func__, chi->ch_index, meta_line->id);

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_WRITE_INT);
	if (!rqd)
		return -ENOMEM;

	m_ctx = nvm_rq_to_pdu(rqd);
	m_ctx->private = meta_line;

	rq_len = rq_ppas * geo->csecs;
	data = ((void *)emeta->buf) + emeta->mem;

	//printBufSample(data);

	bio = qblk_bio_map_addr(qblk, data, rq_ppas, rq_len,
					meta->emeta_alloc_type, GFP_KERNEL);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto fail_free_rqd;
	}
	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	rqd->bio = bio;

	ret = qblk_alloc_w_rq(qblk, rqd, rq_ppas, qblk_end_io_write_meta);
	if (ret)
		goto fail_free_bio;

	for (i = 0; i < rqd->nr_ppas; ) {
		spin_lock(&meta_line->lock);
		newpage =  __qblk_alloc_page(qblk, meta_line, rq_ppas);
		spin_unlock(&meta_line->lock);
		if (rq_ppas == 1) {
			rqd->ppa_addr = newpage;
			i++;
		} else {
			for (j = 0; j < rq_ppas; j++, i++) {
				rqd->ppa_list[i] = newpage;
				newpage = gen_ppa_add_one_inside_chnl(qblk, newpage);
			}
		}
	}

	emeta->mem += rq_len;
	//pr_notice("%s, rq_len=%d,emeta->mem=%d\n",
	//				__func__, rq_len, emeta->mem);
	if (emeta->mem < meta->emeta_len[0]) {
		spin_lock(&chi->close_lock);
		list_add_tail(&meta_line->list, &chi->emeta_list);
		spin_unlock(&chi->close_lock);
	}

	//logentry.type = QBLK_SUBMIT_EMETA;
	//logentry.firstppa = rqd->ppa_list[0];
	//logentry.nr_secs = rqd->nr_ppas;
	//qblk_debug_time_irqsave(qblk, &m_ctx->logindex,chi->ch_index,logentry );

	//printRqdStatus(rqd);
	qblk_calculate_write_amplification(qblk, 1, 0, rq_ppas, 0, 0, 0);
	ret = qblk_submit_io(qblk, rqd);
	if (ret) {
		pr_err("qblk: emeta I/O submission failed: %d\n", ret);
		goto fail_rollback;
	}

	return NVM_IO_OK;

fail_rollback:
	if (emeta->mem >= meta->emeta_len[0]) {
		spin_lock(&chi->close_lock);
		list_add(&meta_line->list, &meta_line->list);
		spin_unlock(&chi->close_lock);
	}
	qblk_dealloc_page(qblk, chi, meta_line, rq_ppas);
fail_free_bio:
	bio_put(bio);
fail_free_rqd:
	qblk_free_rqd(qblk, rqd, QBLK_WRITE_INT);
	return ret;
}

static int qblk_submit_io_set(struct qblk *qblk,
				struct nvm_rq *rqd, unsigned int qcount)
{

	struct ppa_addr erase_ppa;
	struct qblk_line *meta_line;
	int err;
	struct ch_info *chi;
	struct qblk_c_ctx *c_ctx;
	//struct qblk_log_entry logentry;

	qblk_ppa_set_empty(&erase_ppa);

	/* Assign lbas to ppas and populate request structure */
	err = qblk_setup_w_rq(qblk, rqd, qcount, &erase_ppa, &chi);
	if (err) {
		pr_err("qblk: could not setup write request: %d\n", err);
		return NVM_IO_ERR;
	}

	meta_line = qblk_should_submit_meta_io(qblk, rqd, chi);
	//pr_notice("%s:qcount=%u,submit draining write\n",__func__,qcount);

	/* Submit data write for current data line */
	//printRqdStatus(rqd);
	c_ctx = nvm_rq_to_pdu(rqd);
	//logentry.type = QBLK_SUBMIT_IOWRITE;
	//logentry.firstppa = rqd->ppa_list[0];
	//logentry.nr_secs = rqd->nr_ppas;
	//qblk_debug_time_irqsave(qblk, &c_ctx->logindex,chi->ch_index, logentry);
	qblk_calculate_write_amplification(qblk, 1, 0, 0, c_ctx->nr_valid, c_ctx->nr_padded, 0);
	qblk_rq_get_semaphores(qblk, chi, c_ctx->lun_bitmap);
	err = qblk_submit_io(qblk, rqd);
	if (err) {
		pr_err("qblk: data I/O submission failed: %d\n", err);
		return NVM_IO_ERR;
	}

	if (!qblk_ppa_empty(erase_ppa)) {
		/* Submit erase for next data line */
		if (qblk_blk_erase_async(qblk, erase_ppa)) {
			struct qblk_line *e_line = qblk_line_get_erase(chi);
			struct nvm_tgt_dev *dev = qblk->dev;
			struct nvm_geo *geo = &dev->geo;
			int bit;

			atomic_inc(&e_line->left_eblks);
			bit = qblk_ppa_to_posinsidechnl(geo, erase_ppa);
			WARN_ON(!test_and_clear_bit(bit, e_line->erase_bitmap));
		}
	}

	if (meta_line) {
		/* Submit metadata write for previous data line */
		err = qblk_submit_meta_io(qblk, meta_line, chi);
		if (err) {
			pr_err("qblk: metadata I/O submission failed: %d", err);
			return NVM_IO_ERR;
		}
	}

	return NVM_IO_OK;
}

static void qblk_free_write_rqd_bios(struct qblk *qblk, struct nvm_rq *rqd)
{
	struct qblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;

	if (c_ctx->nr_padded)
		qblk_bio_free_pages(qblk, bio, c_ctx->nr_valid,
							c_ctx->nr_padded);
}

static int qblk_drain(struct qblk *qblk,
							unsigned int qcount,
							unsigned long *psaved_time)
{
	struct bio *bio;
	struct nvm_rq *rqd;
	struct qblk_queue *pq;
	unsigned int flush_point;
	unsigned int secs_avail, secs_to_sync, secs_to_com;
	unsigned int secs_to_flush;
	unsigned long pos;
	struct qblk_rb *rb = &qblk->mqrwb[qcount];
	unsigned long this_time = jiffies;

	/* If there are no sectors in the cache, flushes (bios without data)
	 * will be cleared on the cache threads
	 */
	secs_avail = qblk_rb_read_count_for_drain(rb);
	if (!secs_avail)//No available data
		return 1;

	flush_point = atomic_read_acquire(&rb->flush_point);
	secs_to_flush = qblk_rb_flush_point_count(rb, flush_point);

	if (!secs_to_flush && secs_avail < qblk->min_write_pgs) {
		//No flush_point and didn't gather enough pages for wb
		if (*psaved_time &&
				(this_time - *psaved_time) >
					msecs_to_jiffies(300)) {
			/* If data have been waiting in rb for more than 100ms,
			 * force to write them back
			 */
			secs_to_flush = secs_avail;
		} else {
			/* We don't have enough pages to wb.
			 * Record the time if not recorded yet.
			 */
			if (!*psaved_time)
				*psaved_time = this_time;
			return 1;
		}
	}

//start to drain data

	secs_to_sync = qblk_calc_secs_to_sync(qblk, secs_avail, secs_to_flush);
	if (secs_to_sync > qblk->max_write_pgs) {
		pr_err("qblk: bad buffer sync calculation\n");
		return 1;
	}

	qblk_printTimeMonotonic(__func__, __LINE__);

	*psaved_time = 0;

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_WRITE);
	if (!rqd) {
		pr_notice("%s: not enough space for rqd\n", __func__);
		return 1;
	}

	BUG_ON(!secs_to_sync);
	bio = bio_alloc(GFP_KERNEL, secs_to_sync);
	if (!bio)
		goto fail_free_rqd;

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	rqd->bio = bio;
	secs_to_com = (secs_to_sync > secs_avail) ? secs_avail : secs_to_sync;
	pos = qblk_rb_read_commit(rb, secs_to_com);

	pq = &qblk->queues[qcount];
	atomic_add(secs_to_com, &pq->inflight_write_secs);

#ifdef PRINT_QBLK_WB_SIZE
	pr_notice("%s rb %u secs_to_com %u\n",
				__func__, qcount, secs_to_com);
#endif

	if (qblk_rb_read_to_bio(qblk, rb,
				rqd, pos, secs_to_sync, secs_avail)) {
		pr_err("qblk: corrupted write bio\n");
		goto fail_put_bio;
	}

	//pr_notice("%s: writer[%u] starts to kick, pos=%lu, secsToSync=%u, secsAvai=%u\n",
	//							__func__, qcount, pos, secs_to_sync, secs_avail);

	//qblk_debug_complete_time(qblk,index, qcount);
	if (qblk_submit_io_set(qblk, rqd, qcount))
		goto fail_free_bio;
	//qblk_debug_complete_time3(qblk,index, qcount);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(secs_to_sync, &qblk->sub_writes);
#endif

	return 0;

fail_free_bio:
	qblk_free_write_rqd_bios(qblk, rqd);
fail_put_bio:
	bio_put(bio);
fail_free_rqd:
	qblk_free_rqd(qblk, rqd, QBLK_WRITE);

	return 1;
}

int qblk_writer_thread_fn(void *data)
{
	struct qblk_writer_param *param = data;
	struct qblk *qblk = param->qblk;
	unsigned int qcount = param->qcount;
	unsigned long saved_time = 0;

	while (!kthread_should_stop()) {
		if (!qblk_drain(qblk, qcount, &saved_time))
			continue;
		//pr_notice("%s,goto sleep,qcount=%d\n",__func__,qcount);
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
		//pr_notice("%s,wake up,qcount=%d\n",__func__,qcount);
	}
	return 0;
}

void qblk_write_kick(struct qblk *qblk, unsigned int writer_index)
{
	//pr_notice("%s\n",__func__);
	wake_up_process(qblk->mq_writer_ts[writer_index]);
	mod_timer(&qblk->wtimers[writer_index].timer, jiffies + msecs_to_jiffies(QBLK_FUA_MERGE_WINDOW_SIZE));
}


/* kick writer_threads every tick to flush outstanding data */
void qblk_timer_fn(struct timer_list *t)
{
	struct qblk_timer *qt = from_timer(qt, t, timer);
	struct qblk *qblk = qt->qblk;
	int index = qt->index;

	qblk_write_kick(qblk, index);
}

#if 0
void qblk_writeback_timer_fn(struct timer_list *t)
{
	struct qblk *qblk = from_timer(qblk, t, wb_timer);
	int nr_chnls = qblk->nr_channels;
	static unsigned long check_time;
	static unsigned long jiffies_increasement = QBLK_INCREASEMENT_LOW;
	unsigned int sec_per_chwrite = qblk->metainfo.sec_per_chwrite;
	int q_idx = qblk->nr_queues;
	int nr_queues = qblk->nr_queues;
	int busyQueue_threshold = nr_queues >> 1;
	struct qblk_queue *pq;
	int busyQueues;
	unsigned long current_time = jiffies;

	while (q_idx--) {
		pq = &qblk->queues[q_idx];
		if (!atomic_add_unless(&pq->map_chnl, 1, nr_chnls-1))
			atomic_set(&pq->map_chnl, 0);
	}

	if (time_after_eq(jiffies, check_time)) {
		busyQueues = 0;
		for (q_idx = 0; q_idx < nr_queues; q_idx++)
			if (atomic_read(&qblk->queues[q_idx].inflight_write_secs)
							>= sec_per_chwrite)
				busyQueues++;

		if (busyQueues < busyQueue_threshold)
			jiffies_increasement = QBLK_INCREASEMENT_LOW;
		else
			jiffies_increasement =
				(QBLK_INCREASEMENT_HIGH - QBLK_INCREASEMENT_LOW) *
					(busyQueues - busyQueue_threshold) /
						(nr_queues-busyQueue_threshold) + QBLK_INCREASEMENT_LOW;
		check_time = current_time + msecs_to_jiffies(QBLK_WB_CHECK_PERIOD);
	}
	mod_timer(&qblk->wb_timer, jiffies + usecs_to_jiffies(jiffies_increasement));

}
#endif
