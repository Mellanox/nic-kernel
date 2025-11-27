/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BLK_MQ_DMA_H
#define BLK_MQ_DMA_H

#include <linux/blk-mq.h>
#include <linux/pci-p2pdma.h>

struct blk_map_iter {
	struct bvec_iter		iter;
	struct bio			*bio;
	struct bio_vec			*bvecs;
	bool				is_integrity;
};

struct blk_dma_iter {
	/* Output address range for this iteration */
	dma_addr_t			addr;
	u32				len;

	/* Status code. Only valid when blk_rq_dma_map_iter_* returned false */
	blk_status_t			status;

	/* Internal to blk_rq_dma_map_iter_* */
	struct blk_map_iter		iter;
	struct pci_p2pdma_map_state	p2pdma;
};

bool blk_rq_dma_map_iter_start(struct request *req, struct device *dma_dev,
		struct dma_iova_state *state, struct blk_dma_iter *iter);
bool blk_rq_dma_map_iter_next(struct request *req, struct device *dma_dev,
		struct dma_iova_state *state, struct blk_dma_iter *iter);
bool blk_rq_dma_unmap(struct request *req, struct device *dma_dev,
		struct dma_iova_state *state, size_t mapped_len);

/**
 * blk_rq_dma_map_coalesce - were all segments coalesced?
 * @state: DMA state to check
 *
 * Returns true if blk_rq_dma_map_iter_start coalesced all segments into a
 * single DMA range.
 */
static inline bool blk_rq_dma_map_coalesce(struct dma_iova_state *state)
{
	return dma_use_iova(state);
}

#endif /* BLK_MQ_DMA_H */
