#include"qblk.h"

#if 0
struct qblk_recov_alloc {
	struct ppa_addr *ppa_list;
	void *meta_list;
	struct nvm_rq *rqd;
	void *data;
	dma_addr_t dma_ppa_list;
	dma_addr_t dma_meta_list;
};

static int qblk_calc_sec_in_line(struct qblk *qblk, struct qblk_line *line)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	int nr_bb = bitmap_weight(line->blk_bitmap, meta->blk_per_chline);

	return meta->sec_per_chline - meta->smeta_sec - meta->emeta_sec[0] -
				nr_bb * geo->clba;
}
#endif

/* Check the CRC of emeta, return 0 if succeed. */
int qblk_recov_check_emeta(struct qblk *qblk, struct chnl_emeta *emeta_buf)
{
	u32 crc;

	crc = qblk_calc_emeta_crc(qblk, emeta_buf);
	if (le32_to_cpu(emeta_buf->crc) != crc)
		return -1;

	if (le32_to_cpu(emeta_buf->header.identifier) != QBLK_MAGIC)
		return -2;

	return 0;
}

#if 0
static int qblk_recov_l2p_from_emeta(struct qblk *qblk,
						struct ch_info *chi, struct qblk_line *line)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_emeta *emeta = line->emeta;
	struct chnl_emeta *emeta_buf = emeta->buf;
	__le64 *lba_list;
	u64 data_start, data_end;
	u64 nr_valid_lbas, nr_lbas = 0;
	u64 qhw_nrlbas = 0;
	u64 i;

	lba_list = emeta_to_lbas(qblk, emeta_buf);
	if (!lba_list)
		return 1;

	data_start = qblk_line_smeta_start(qblk, line) + meta->smeta_sec;
	data_end = line->emeta_ssec;
	nr_valid_lbas = le64_to_cpu(emeta_buf->nr_valid_lbas);

	for (i = data_start; i < data_end; i++) {
		struct ppa_addr ppa;
		int pos;

		ppa = offset_in_line_to_gen_ppa(qblk, i, chi->ch_index, line->id);
		pos = qblk_ppa_to_posinsidechnl(geo, ppa);

		/* Do not update bad blocks */
		if (test_bit(pos, line->blk_bitmap)) {
			pr_notice("%s, line %u pos %u i %llu is bad\n",
							__func__, line->id, pos, i);
			continue;
		}

		if (le64_to_cpu(lba_list[i]) == ADDR_EMPTY) {
			pr_notice("%s, line %u pos %u i %llu is EMPTY\n",
							__func__, line->id, pos, i);
			spin_lock(&line->lock);
			if (test_and_set_bit(i, line->invalid_bitmap))
				WARN_ONCE(1, "qblk: rec. double invalidate:\n");
			else
				le32_add_cpu(line->vsc, -1);
			spin_unlock(&line->lock);

			continue;
		}

		qhw_nrlbas++;
		if (qblk_update_map_test(qblk, le64_to_cpu(lba_list[i]), ppa))
			qhw_nrlbas--;
		nr_lbas++;
	}

	if (nr_valid_lbas != nr_lbas)
		pr_err("line %d - inconsistent lba list(%llu/%llu) qhw(%llu)\n",
				line->id, nr_valid_lbas, nr_lbas, qhw_nrlbas);

	line->left_msecs = 0;

	return 0;
}

#if 0
/* When this function is called, it means that not all upper pages have been
 * written in a page that contains valid data. In order to recover this data, we
 * first find the write pointer on the device, then we pad all necessary
 * sectors, and finally attempt to read the valid data
 */
static int qblk_recov_scan_all_oob(struct qblk *qblk, struct qblk_line *line,
				   struct qblk_recov_alloc p)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct nvm_rq *rqd;
	struct bio *bio;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	u64 w_ptr = 0, r_ptr;
	int rq_ppas, rq_len;
	int i, j;
	int ret = 0;
	int rec_round;
	int left_ppas = qblk_calc_sec_in_line(qblk, line) - line->cur_sec;

	ppa_list = p.ppa_list;
	meta_list = p.meta_list;
	rqd = p.rqd;
	data = p.data;
	dma_ppa_list = p.dma_ppa_list;
	dma_meta_list = p.dma_meta_list;

	/* we could recover up until the line write pointer */
	r_ptr = line->cur_sec;
	rec_round = 0;

next_rq:
	memset(rqd, 0, pblk_g_rq_size);

	rq_ppas = qblk_calc_secs(qblk, left_ppas, 0);
	if (!rq_ppas)
		rq_ppas = qblk->min_write_pgs;
	rq_len = rq_ppas * geo->csecs;

	bio = bio_map_kern(dev->q, data, rq_len, GFP_KERNEL);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	rqd->bio = bio;
	rqd->opcode = NVM_OP_PREAD;
	rqd->meta_list = meta_list;
	rqd->nr_ppas = rq_ppas;
	rqd->ppa_list = ppa_list;
	rqd->dma_ppa_list = dma_ppa_list;
	rqd->dma_meta_list = dma_meta_list;

	if (qblk_io_aligned(qblk, rq_ppas))
		rqd->flags = qblk_set_read_mode(pblk, QBLK_READ_SEQUENTIAL);
	else
		rqd->flags = qblk_set_read_mode(pblk, QBLK_READ_RANDOM);

	for (i = 0; i < rqd->nr_ppas; ) {
		struct ppa_addr ppa;
		int pos;

		w_ptr = pblk_alloc_page(pblk, line, pblk->min_write_pgs);
		ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
		pos = pblk_ppa_to_pos(geo, ppa);

		while (test_bit(pos, line->blk_bitmap)) {
			w_ptr += pblk->min_write_pgs;
			ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
			pos = pblk_ppa_to_pos(geo, ppa);
		}

		for (j = 0; j < pblk->min_write_pgs; j++, i++, w_ptr++)
			rqd->ppa_list[i] =
				addr_to_gen_ppa(pblk, w_ptr, line->id);
	}

	ret = qblk_submit_io_sync(qblk, rqd);
	if (ret) {
		pr_err("qblk: I/O submission failed: %d\n", ret);
		return ret;
	}

	atomic_dec(&qblk->inflight_io);

	/* This should not happen since the read failed during normal recovery,
	 * but the media works funny sometimes...
	 */
	if (!rec_round++ && !rqd->error) {
		rec_round = 0;
		for (i = 0; i < rqd->nr_ppas; i++, r_ptr++) {
			u64 lba = le64_to_cpu(meta_list[i].lba);

			if (lba == ADDR_EMPTY || lba > pblk->rl.nr_secs)
				continue;

			qblk_update_map(qblk, lba, rqd->ppa_list[i]);
		}
	}

	/* Reached the end of the written line */
	if (rqd->error == NVM_RSP_ERR_EMPTYPAGE) {
		int pad_secs, nr_error_bits, bit;
		int ret;

		bit = find_first_bit((void *)&rqd->ppa_status, rqd->nr_ppas);
		nr_error_bits = rqd->nr_ppas - bit;

		/* Roll back failed sectors */
		line->cur_sec -= nr_error_bits;
		line->left_msecs += nr_error_bits;
		bitmap_clear(line->map_bitmap, line->cur_sec, nr_error_bits);

		pad_secs = pblk_pad_distance(pblk);
		if (pad_secs > line->left_msecs)
			pad_secs = line->left_msecs;

		ret = pblk_recov_pad_oob(pblk, line, pad_secs);
		if (ret)
			pr_err("pblk: OOB padding failed (err:%d)\n", ret);

		ret = pblk_recov_read_oob(pblk, line, p, r_ptr);
		if (ret)
			pr_err("qblk: OOB read failed (err:%d)\n", ret);

		left_ppas = 0;
	}

	left_ppas -= rq_ppas;
	if (left_ppas > 0)
		goto next_rq;

	return ret;
}

static int qblk_recov_scan_oob(struct qblk *qblk, struct ch_info *chi,
					struct qblk_line *line,
					struct qblk_recov_alloc p, int *done)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr *ppa_list;
	struct qblk_sec_meta *meta_list;
	struct nvm_rq *rqd;
	struct bio *bio;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	u64 paddr = qblk_line_smeta_start(qblk, line) + meta->smeta_sec;
	int rq_ppas, rq_len;
	int i, j;
	int ret = 0;
	int left_ppas = qblk_calc_sec_in_line(qblk, line);

	ppa_list = p.ppa_list;
	meta_list = p.meta_list;
	rqd = p.rqd;
	data = p.data;
	dma_ppa_list = p.dma_ppa_list;
	dma_meta_list = p.dma_meta_list;

	*done = 1;

next_rq:
	memset(rqd, 0, qblk_g_rq_size);

	rq_ppas = qblk_calc_secs(qblk, left_ppas, 0);
	if (!rq_ppas)
		rq_ppas = qblk->min_write_pgs;
	rq_len = rq_ppas * geo->csecs;

	bio = bio_map_kern(dev->q, data, rq_len, GFP_KERNEL);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	rqd->bio = bio;
	rqd->opcode = NVM_OP_PREAD;
	rqd->meta_list = meta_list;
	rqd->nr_ppas = rq_ppas;
	rqd->ppa_list = ppa_list;
	rqd->dma_ppa_list = dma_ppa_list;
	rqd->dma_meta_list = dma_meta_list;

	if (qblk_io_aligned(qblk, rq_ppas))
		rqd->flags = qblk_set_read_mode(qblk, QBLK_READ_SEQUENTIAL);
	else
		rqd->flags = qblk_set_read_mode(qblk, QBLK_READ_RANDOM);

	for (i = 0; i < rqd->nr_ppas; ) {
		struct ppa_addr ppa;
		int pos;

		ppa = offset_in_line_to_gen_ppa(qblk, paddr, chi->ch_index, line->id);
		pos = qblk_ppa_to_posinsidechnl(geo, ppa);

		while (test_bit(pos, line->blk_bitmap)) {
			paddr += qblk->min_write_pgs;
			ppa = offset_in_line_to_gen_ppa(qblk, paddr, chi->ch_index, line->id);
			pos = qblk_ppa_to_posinsidechnl(geo, ppa);
		}

		for (j = 0; j < qblk->min_write_pgs; j++, i++, paddr++)
			rqd->ppa_list[i] =
				offset_in_line_to_gen_ppa(qblk, paddr, chi->ch_index, line->id);
	}

	ret = qblk_submit_io_sync(qblk, rqd);
	if (ret) {
		pr_err("qblk: I/O submission failed: %d\n", ret);
		bio_put(bio);
		return ret;
	}

	atomic_dec(&qblk->inflight_io);

	/* Reached the end of the written line */
	if (rqd->error) {
		int nr_error_bits, bit;

		bit = find_first_bit((void *)&rqd->ppa_status, rqd->nr_ppas);
		nr_error_bits = rqd->nr_ppas - bit;

		/* Roll back failed sectors */
		line->cur_sec -= nr_error_bits;
		line->left_msecs += nr_error_bits;
		bitmap_clear(line->map_bitmap, line->cur_sec, nr_error_bits);

		left_ppas = 0;
		rqd->nr_ppas = bit;

		if (rqd->error != NVM_RSP_ERR_EMPTYPAGE)
			*done = 0;
	}

	for (i = 0; i < rqd->nr_ppas; i++) {
		u64 lba = le64_to_cpu(meta_list[i].lba);

		if (lba == ADDR_EMPTY || lba > qblk->rl.nr_secs)
			continue;

		qblk_update_map(qblk, lba, rqd->ppa_list[i]);
	}

	left_ppas -= rq_ppas;
	if (left_ppas > 0)
		goto next_rq;

	return ret;
}
#endif

/* Scan line for lbas on out of bound area */
static int qblk_recov_l2p_from_oob(struct qblk *qblk,
						struct ch_info *chi, struct qblk_line *line)
{
	return 0;

#if 0
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct nvm_rq *rqd;
	struct ppa_addr *ppa_list;
	struct qblk_sec_meta *meta_list;
	struct qblk_recov_alloc p;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	int done, ret = 0;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
	if (!meta_list)
		return -ENOMEM;

	ppa_list = (void *)(meta_list) + qblk_dma_meta_size(qblk);
	dma_ppa_list = dma_meta_list + qblk_dma_meta_size(qblk);

	data = kcalloc(qblk->max_write_pgs, geo->csecs, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto free_meta_list;
	}

	rqd = qblk_alloc_rqd_nowait(qblk, QBLK_READ);
	//TODO:rqd==NULL

	p.ppa_list = ppa_list;
	p.meta_list = meta_list;
	p.rqd = rqd;
	p.data = data;
	p.dma_ppa_list = dma_ppa_list;
	p.dma_meta_list = dma_meta_list;

	ret = qblk_recov_scan_oob(qblk, chi, line, p, &done);
	if (ret) {
		pr_err("qblk: could not recover L2P from OOB\n");
		goto out;
	}

	if (!done) {
		ret = qblk_recov_scan_all_oob(qblk, line, p);
		if (ret) {
			pr_err("qblk: could not recover L2P from OOB\n");
			goto out;
		}
	}

	if (qblk_line_is_full(line))
		qblk_line_recov_close(qblk, line);

out:
	kfree(data);
free_meta_list:
	nvm_dev_dma_free(dev->parent, meta_list, dma_meta_list);

	return ret;
#endif
}


/* Insert lines ordered by sequence number (seq_num) on list */
static void qblk_recov_line_add_ordered(struct list_head *head,
					struct qblk_line *line)
{
	struct qblk_line *t = NULL;

	list_for_each_entry(t, head, list)
		if (t->seq_nr > line->seq_nr)
			break;

	__list_add(&line->list, t->list.prev, &t->list);
}

static u64 qblk_line_emeta_start(struct qblk *qblk, struct ch_info *chi, struct qblk_line *line)
{
	struct nvm_tgt_dev *dev = qblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct qblk_metainfo *meta = &qblk->metainfo;
	unsigned int emeta_secs;
	u64 emeta_start;
	struct ppa_addr ppa;
	int pos;

	emeta_secs = meta->emeta_sec[0];
	emeta_start = meta->sec_per_chline;

	while (emeta_secs) {
		emeta_start--;
		ppa = offset_in_line_to_gen_ppa(qblk,
				emeta_start, chi->ch_index, line->id);
		pos = qblk_ppa_to_posinsidechnl(geo, ppa);
		if (!test_bit(pos, line->blk_bitmap))
			emeta_secs--;
	}

	return emeta_start;
}
#endif

/* Return 0 if succeed. */
int qblk_recov_l2p(struct qblk *qblk)
{
	struct qblk_metainfo *meta = &qblk->metainfo;
	struct ch_info *chi;
	//int valid_uuid = 0;
	struct qblk_smeta *smeta;
	struct qblk_emeta *emeta;
	struct chnl_smeta *smeta_buf;
	int found_lines = 0, recovered_lines = 0;
	int ch_idx;
	LIST_HEAD(recov_list);

	for (ch_idx = 0; ch_idx < qblk->nr_channels; ch_idx++) {
		int meta_line;
		//int open_lines = 0;
		int i;
		struct qblk_line *line;
		//int is_next = 0;
		//struct qblk_line *tline, *data_line = NULL;

		chi = &qblk->ch[ch_idx];
		spin_lock(&chi->free_lock);
		meta_line = find_first_zero_bit(&chi->meta_bitmap,
							QBLK_DATA_LINES);
		set_bit(meta_line, &chi->meta_bitmap);
		smeta = chi->sline_meta[meta_line];
		emeta = chi->eline_meta[meta_line];
		smeta_buf = (struct chnl_smeta *)smeta;
		spin_unlock(&chi->free_lock);

		for (i = 0; i < chi->nr_lines; i++) {
			u32 crc;

			line = &chi->lines[i];

			memset(smeta, 0, meta->smeta_len);
			line->smeta = smeta;
			line->lun_bitmap = ((void *)(smeta_buf)) +
							sizeof(struct chnl_smeta);

			/* Lines that cannot be read are assumed as not written here */
			if (qblk_line_read_smeta(qblk, line))
				continue;

			crc = qblk_calc_smeta_crc(qblk, smeta_buf);
			if (le32_to_cpu(smeta_buf->crc) != crc)
				continue;

			if (le32_to_cpu(smeta_buf->header.identifier)
							!= QBLK_MAGIC)
				continue;

			//TODO: For now, QBLK only supports a fresh setup.
#if 0
			if (smeta_buf->header.version != SMETA_VERSION) {
				pr_err("qblk: found incompatible line version %u\n",
						le16_to_cpu(smeta_buf->header.version));
				continue;
			}

			/* The first valid instance uuid is used for initialization */
			if (!valid_uuid) {
				memcpy(qblk->instance_uuid, smeta_buf->header.uuid, 16);
				valid_uuid = 1;
			}

			if (memcmp(qblk->instance_uuid, smeta_buf->header.uuid, 16)) {
				pr_debug("qblk: ignore line %u due to uuid mismatch\n",
						i);
				continue;
			}

			/* Update line metadata */
			spin_lock(&line->lock);
			line->id = le32_to_cpu(smeta_buf->header.id);
			WARN_ON(line->id != i);
			line->type = le16_to_cpu(smeta_buf->header.type);
			line->seq_nr = le64_to_cpu(smeta_buf->seq_nr);
			spin_unlock(&line->lock);

			/* Update general metadata */
			spin_lock(&chi->free_lock);
			if (line->seq_nr >= chi->d_seq_nr)
				chi->d_seq_nr = line->seq_nr + 1;
			chi->nr_free_lines--;
			spin_unlock(&chi->free_lock);

			if (qblk_line_recov_alloc(qblk, chi, line)) {
				goto next_chnl;
			}

			qblk_recov_line_add_ordered(&recov_list, line);
			found_lines++;
			//pr_notice("qblk: recovering data line %d, seq:%llu\n",
			//		line->id, smeta_buf->seq_nr);
#endif
		}

		if (!found_lines) {
			qblk_setup_uuid(qblk);

			spin_lock(&chi->free_lock);
			WARN_ON_ONCE(!test_and_clear_bit(meta_line,
							&chi->meta_bitmap));
			spin_unlock(&chi->free_lock);

			goto next_chnl;
		}

#if 0
		/* Verify closed blocks and recover this portion of L2P table*/
		list_for_each_entry_safe(line, tline, &recov_list, list) {
			recovered_lines++;

			line->emeta_ssec = qblk_line_emeta_start(qblk, chi, line);
			line->emeta = emeta;
			memset(line->emeta->buf, 0, meta->emeta_len[0]);

			if (qblk_line_read_emeta(qblk, line, line->emeta->buf)) {
				qblk_recov_l2p_from_oob(qblk, chi, line);
				goto next;
			}

			if (qblk_recov_check_emeta(qblk, line->emeta->buf)) {
				qblk_recov_l2p_from_oob(qblk, chi, line);
				goto next;
			}

			if (qblk_recov_l2p_from_emeta(qblk, chi, line))
				qblk_recov_l2p_from_oob(qblk, chi, line);

next:
			if (qblk_line_is_full(line)) {
				struct list_head *move_list;

				spin_lock(&line->lock);
				line->state = QBLK_LINESTATE_CLOSED;
				move_list = qblk_line_gc_list(qblk, chi, line);
				spin_unlock(&line->lock);

				spin_lock(&chi->gc_lock);
				list_move_tail(&line->list, move_list);
				spin_unlock(&chi->gc_lock);

				kfree(line->map_bitmap);
				line->map_bitmap = NULL;
				line->smeta = NULL;
				line->emeta = NULL;
			} else {
				if (open_lines > 1)
					pr_err("qblk: failed to recover L2P\n");

				open_lines++;
				line->meta_line = meta_line;
				data_line = line;
			}
		}

		spin_lock(&chi->free_lock);
		if (!open_lines) {
			WARN_ON_ONCE(!test_and_clear_bit(meta_line,
								&chi->meta_bitmap));
			qblk_line_replace_data(qblk);
			qblk_line_replace_data(qblk, chi, struct qblk_line * cur, struct qblk_line * newline);
		} else {
			/* Allocate next line for preparation */
			chi->data_next = qblk_line_get(qblk, chi);
			if (chi->data_next) {
				chi->data_next->seq_nr = chi->d_seq_nr++;
				chi->data_next->type = QBLK_LINETYPE_DATA;
				is_next = 1;
			}
		}
		spin_unlock(&chi->free_lock);

		if (is_next)
			qblk_line_erase(qblk, ch_idx, chi->data_next);
#endif
next_chnl:
		if (found_lines != recovered_lines) {
			pr_err("%s, failed to recover lines ch=%d, found_lines=%d, recovered_lines=%d\n",
							__func__, chi->ch_index, found_lines, recovered_lines);
			return -EIO;
		}
	}

	return 0;

}

