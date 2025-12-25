/*
 * Copyright (c) 2018, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "port_buffer.h"

#define CABLE_DELAY_CALC_ACCURACY_FACTOR (1000)
#define MLX5E_ACCURATE_FACTOR (100)
#define MLX5E_INTER_PACKET_GAP (20)
#define MINIMAL_PACKET_SIZE (64)
/*
 * MLX5E_CABLE_FACTOR =
 *	(CABLE_DELAY_CALC_ACCURACY_FACTOR * CABLE_BIDIR * BITS_IN_GBIT) /
 *	(SPEED_OF_LIGHT_IN_FIBER * BITS_IN_BYTE) =
 *	((1000 * 2 * 10^9) / (1.98 * 10^8 * 8)) = 1262
 */
#define MLX5E_CABLE_FACTOR (1262)

int mlx5e_port_query_buffer(struct mlx5e_priv *priv,
			    struct mlx5e_port_buffer *port_buffer)
{
	u16 port_buff_cell_sz = priv->dcbx.port_buff_cell_sz;
	struct mlx5_core_dev *mdev = priv->mdev;
	int sz = MLX5_ST_SZ_BYTES(pbmc_reg);
	u32 total_used = 0;
	void *buffer;
	void *out;
	int err;
	int i;

	out = kzalloc(sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5e_port_query_pbmc(mdev, out);
	if (err)
		goto out;

	for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
		buffer = MLX5_ADDR_OF(pbmc_reg, out, buffer[i]);
		port_buffer->buffer[i].lossy =
			MLX5_GET(bufferx_reg, buffer, lossy);
		port_buffer->buffer[i].epsb =
			MLX5_GET(bufferx_reg, buffer, epsb);
		port_buffer->buffer[i].size =
			MLX5_GET(bufferx_reg, buffer, size) * port_buff_cell_sz;
		port_buffer->buffer[i].xon =
			MLX5_GET(bufferx_reg, buffer, xon_threshold) * port_buff_cell_sz;
		port_buffer->buffer[i].xoff =
			MLX5_GET(bufferx_reg, buffer, xoff_threshold) * port_buff_cell_sz;
		total_used += port_buffer->buffer[i].size;

		netdev_dbg(priv->netdev, "buffer %d: size=%d, xon=%d, xoff=%d, epsb=%d, lossy=%d\n",
			   i,
			   port_buffer->buffer[i].size,
			   port_buffer->buffer[i].xon,
			   port_buffer->buffer[i].xoff,
			   port_buffer->buffer[i].epsb,
			   port_buffer->buffer[i].lossy);
	}

	port_buffer->internal_buffers_size = 0;
	for (i = MLX5E_MAX_NETWORK_BUFFER; i < MLX5E_TOTAL_BUFFERS; i++) {
		buffer = MLX5_ADDR_OF(pbmc_reg, out, buffer[i]);
		port_buffer->internal_buffers_size +=
			MLX5_GET(bufferx_reg, buffer, size) * port_buff_cell_sz;
	}

	port_buffer->port_buffer_size =
		MLX5_GET(pbmc_reg, out, port_buffer_size) * port_buff_cell_sz;
	port_buffer->headroom_size = total_used;
	port_buffer->spare_buffer_size = port_buffer->port_buffer_size -
					 port_buffer->internal_buffers_size -
					 port_buffer->headroom_size;

	netdev_dbg(priv->netdev,
		   "total buffer size=%u, headroom buffer size=%u, internal buffers size=%u, spare buffer size=%u\n",
		   port_buffer->port_buffer_size, port_buffer->headroom_size,
		   port_buffer->internal_buffers_size,
		   port_buffer->spare_buffer_size);
out:
	kfree(out);
	return err;
}

struct mlx5e_buffer_pool {
	u32 infi_size;
	u32 size;
	u32 buff_occupancy;
};

static int mlx5e_port_query_pool(struct mlx5_core_dev *mdev,
				 struct mlx5e_buffer_pool *buffer_pool,
				 u32 desc, u8 dir, u8 pool_idx)
{
	u32 out[MLX5_ST_SZ_DW(sbpr_reg)] = {};
	int err;

	err = mlx5e_port_query_sbpr(mdev, desc, dir, pool_idx, out,
				    sizeof(out));
	if (err)
		return err;

	buffer_pool->size = MLX5_GET(sbpr_reg, out, size);
	buffer_pool->infi_size = MLX5_GET(sbpr_reg, out, infi_size);
	buffer_pool->buff_occupancy = MLX5_GET(sbpr_reg, out, buff_occupancy);

	return err;
}

enum {
	MLX5_INGRESS_DIR = 0,
	MLX5_EGRESS_DIR = 1,
};

enum {
	MLX5_LOSSY_POOL = 0,
	MLX5_LOSSLESS_POOL = 1,
};

/* No limit on usage of shared buffer pool (max_buff=0) */
#define MLX5_SB_POOL_NO_THRESHOLD  0
/* Shared buffer pool usage threshold when calculated
 * dynamically in alpha units. alpha=13 is equivalent to
 * HW_alpha of  [(1/128) * 2 ^ (alpha-1)] = 32, where HW_alpha
 * equates to the following portion of the shared buffer pool:
 * [32 / (1 + n * 32)] While *n* is the number of buffers
 * that are using the shared buffer pool.
 */
#define MLX5_SB_POOL_THRESHOLD 13

/* Shared buffer class management parameters */
struct mlx5_sbcm_params {
	u8 pool_idx;
	u8 max_buff;
	u8 infi_size;
};

static const struct mlx5_sbcm_params sbcm_default = {
	.pool_idx = MLX5_LOSSY_POOL,
	.max_buff = MLX5_SB_POOL_NO_THRESHOLD,
	.infi_size = 0,
};

static const struct mlx5_sbcm_params sbcm_lossy = {
	.pool_idx = MLX5_LOSSY_POOL,
	.max_buff = MLX5_SB_POOL_NO_THRESHOLD,
	.infi_size = 1,
};

static const struct mlx5_sbcm_params sbcm_lossless = {
	.pool_idx = MLX5_LOSSLESS_POOL,
	.max_buff = MLX5_SB_POOL_THRESHOLD,
	.infi_size = 0,
};

static const struct mlx5_sbcm_params sbcm_lossless_no_threshold = {
	.pool_idx = MLX5_LOSSLESS_POOL,
	.max_buff = MLX5_SB_POOL_NO_THRESHOLD,
	.infi_size = 1,
};

/**
 * select_sbcm_params() - selects the shared buffer pool configuration
 *
 * @buffer: <input> port buffer to retrieve params of
 * @lossless_buff_count: <input> number of lossless buffers in total
 *
 * The selection is based on the following rules:
 * 1. If buffer size is 0, no shared buffer pool is used.
 * 2. If buffer is lossy, use lossy shared buffer pool.
 * 3. If there are more than 1 lossless buffers, use lossless shared buffer pool
 *    with threshold.
 * 4. If there is only 1 lossless buffer, use lossless shared buffer pool
 *    without threshold.
 *
 * @return const struct mlx5_sbcm_params* selected values
 */
static const struct mlx5_sbcm_params *
select_sbcm_params(struct mlx5e_bufferx_reg *buffer, u8 lossless_buff_count)
{
	if (buffer->size == 0)
		return &sbcm_default;

	if (buffer->lossy)
		return &sbcm_lossy;

	if (lossless_buff_count > 1)
		return &sbcm_lossless;

	return &sbcm_lossless_no_threshold;
}

static int port_update_pool_cfg(struct mlx5_core_dev *mdev,
				struct mlx5e_port_buffer *port_buffer)
{
	const struct mlx5_sbcm_params *p;
	u8 lossless_buff_count = 0;
	int err;
	int i;

	if (!MLX5_CAP_GEN(mdev, sbcam_reg))
		return 0;

	for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++)
		lossless_buff_count += ((port_buffer->buffer[i].size) &&
				       (!(port_buffer->buffer[i].lossy)));

	for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
		p = select_sbcm_params(&port_buffer->buffer[i], lossless_buff_count);
		err = mlx5e_port_set_sbcm(mdev, 0, i,
					  MLX5_INGRESS_DIR,
					  p->infi_size,
					  p->max_buff,
					  p->pool_idx);
		if (err)
			return err;
	}

	return 0;
}

static int port_update_shared_buffer(struct mlx5_core_dev *mdev,
				     u32 current_headroom_size,
				     u32 new_headroom_size)
{
	struct mlx5e_buffer_pool lossless_ipool;
	struct mlx5e_buffer_pool lossy_epool;
	u32 lossless_ipool_size;
	u32 shared_buffer_size;
	u32 total_buffer_size;
	u32 lossy_epool_size;
	int err;

	if (!MLX5_CAP_GEN(mdev, sbcam_reg))
		return 0;

	err = mlx5e_port_query_pool(mdev, &lossy_epool, 0, MLX5_EGRESS_DIR,
				    MLX5_LOSSY_POOL);
	if (err)
		return err;

	err = mlx5e_port_query_pool(mdev, &lossless_ipool, 0, MLX5_INGRESS_DIR,
				    MLX5_LOSSLESS_POOL);
	if (err)
		return err;

	total_buffer_size = current_headroom_size + lossy_epool.size +
			    lossless_ipool.size;
	shared_buffer_size = total_buffer_size - new_headroom_size;

	if (shared_buffer_size < 4) {
		pr_err("Requested port buffer is too large, not enough space left for shared buffer\n");
		return -EINVAL;
	}

	/* Total shared buffer size is split in a ratio of 3:1 between
	 * lossy and lossless pools respectively.
	 */
	lossless_ipool_size = shared_buffer_size / 4;
	lossy_epool_size    = shared_buffer_size - lossless_ipool_size;

	mlx5e_port_set_sbpr(mdev, 0, MLX5_EGRESS_DIR, MLX5_LOSSY_POOL, 0,
			    lossy_epool_size);
	mlx5e_port_set_sbpr(mdev, 0, MLX5_INGRESS_DIR, MLX5_LOSSLESS_POOL, 0,
			    lossless_ipool_size);
	return 0;
}

static int port_set_buffer(struct mlx5e_priv *priv,
			   struct mlx5e_port_buffer *port_buffer)
{
	u16 port_buff_cell_sz = priv->dcbx.port_buff_cell_sz;
	struct mlx5_core_dev *mdev = priv->mdev;
	int sz = MLX5_ST_SZ_BYTES(pbmc_reg);
	u32 current_headroom_cells = 0;
	u32 new_headroom_cells = 0;
	void *in;
	int err;
	int i;

	in = kzalloc(sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	err = mlx5e_port_query_pbmc(mdev, in);
	if (err)
		goto out;

	for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
		void *buffer = MLX5_ADDR_OF(pbmc_reg, in, buffer[i]);
		current_headroom_cells += MLX5_GET(bufferx_reg, buffer, size);

		u64 size = port_buffer->buffer[i].size;
		u64 xoff = port_buffer->buffer[i].xoff;
		u64 xon = port_buffer->buffer[i].xon;

		size = DIV_ROUND_UP(size, port_buff_cell_sz);
		new_headroom_cells += size;
		xoff = DIV_ROUND_UP(xoff, port_buff_cell_sz);
		xon = DIV_ROUND_UP(xon, port_buff_cell_sz);
		MLX5_SET(bufferx_reg, buffer, size, size);
		MLX5_SET(bufferx_reg, buffer, lossy, port_buffer->buffer[i].lossy);
		MLX5_SET(bufferx_reg, buffer, xoff_threshold, xoff);
		MLX5_SET(bufferx_reg, buffer, xon_threshold, xon);
	}

	err = port_update_shared_buffer(priv->mdev, current_headroom_cells,
					new_headroom_cells);
	if (err)
		goto out;

	err = port_update_pool_cfg(priv->mdev, port_buffer);
	if (err)
		goto out;

	/* RO bits should be set to 0 on write */
	MLX5_SET(pbmc_reg, in, port_buffer_size, 0);

	err = mlx5e_port_set_pbmc(mdev, in);
out:
	kfree(in);
	return err;
}

int mlx5e_port_set_cable_len(struct mlx5e_priv *priv, u16 length_in_meters)
{
	struct mlx5_core_dev *dev = priv->mdev;

	if (length_in_meters > MLX5_MAX_CABLE_LENGTH) {
		mlx5_core_err(dev, "Cable length: (%u) exceeds max: (%u)\n",
			      length_in_meters, MLX5_MAX_CABLE_LENGTH);
		return -EINVAL;
	}

	if (!MLX5_CAP_PCAM_FEATURE(dev, cable_length)) {
		if (!length_in_meters) {
			mlx5_core_err(dev, "Cable length cannot be set to zero\n");
			return -EINVAL;
		}
		priv->dcbx.cable_len = length_in_meters;
		return 0;
	}
	return mlx5_set_port_cable_len(dev, length_in_meters);
}

int mlx5e_port_get_cable_len(struct mlx5e_priv *priv, u16 *length_in_meters)
{
	if (!MLX5_CAP_PCAM_FEATURE(priv->mdev, cable_length)) {
		*length_in_meters = priv->dcbx.cable_len;
		return 0;
	}

	return mlx5_query_port_cable_len(priv->mdev, length_in_meters);
}

struct mlx5e_pause_quanta_entry {
	u32 speed_mbps;
	u32 num_quantas;
};

/* Keep array sorted when adding new speeds */
static const struct mlx5e_pause_quanta_entry mlx5e_pause_quanta_tbl[] = {
	{ SPEED_25000, 80 },
	{ SPEED_40000, 118 },
	{ SPEED_100000, 394 },
	{ SPEED_200000, 453 },
	{ SPEED_400000, 905 },
	{ SPEED_800000, 1810 },
	{ SPEED_1600000, 3620 },
};

#define MLX5E_PAUSE_QUANTA_SIZE_BYTES 64
static int mlx5e_get_mac_response_time_bytes(u32 port_speed_mbs)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mlx5e_pause_quanta_tbl) - 1; i++)
		if (port_speed_mbs <= mlx5e_pause_quanta_tbl[i].speed_mbps)
			break;

	return mlx5e_pause_quanta_tbl[i].num_quantas *
	       MLX5E_PAUSE_QUANTA_SIZE_BYTES;
}

static int mlx5e_calculate_buf_sz_and_thresholds(struct mlx5e_priv *priv,
						 u32 *xoff, u32 *xon,
						 u16 max_mtu,
						 u32 *lossless_buffer_sz)
{
	u32 mac_rsp_time_bytes, buffer_minus_xoff_bytes;
	u32 cable_len_bytes, port_speed_mbs;
	u16 oper_mtu, cable_len_meters;
	int cell_factor, err;

	err = mlx5e_port_linkspeed(priv->mdev, &port_speed_mbs);
	if (err)
		return err;

	mlx5_query_port_oper_mtu(priv->mdev, &oper_mtu, 1);

	mac_rsp_time_bytes = mlx5e_get_mac_response_time_bytes(port_speed_mbs);

	err = mlx5e_port_get_cable_len(priv, &cable_len_meters);
	if (err)
		return err;
 
	cable_len_bytes = cable_len_meters * (port_speed_mbs / 1000) *
			  MLX5E_CABLE_FACTOR / CABLE_DELAY_CALC_ACCURACY_FACTOR;

	cell_factor = priv->dcbx.port_buff_cell_sz * MLX5E_ACCURATE_FACTOR /
			   (MLX5E_INTER_PACKET_GAP + MINIMAL_PACKET_SIZE);

	buffer_minus_xoff_bytes  = (cable_len_bytes +
				    2 * mac_rsp_time_bytes + oper_mtu) *
				   cell_factor / MLX5E_ACCURATE_FACTOR +
				   oper_mtu;
	*xon = buffer_minus_xoff_bytes - oper_mtu + port_speed_mbs / 8;
	*xoff = *xon + 2 * max_mtu;
	*lossless_buffer_sz = buffer_minus_xoff_bytes + *xoff;

	return 0;
}

static int get_buffer_max_cell_size(struct mlx5_core_dev *mdev,
				    struct mlx5e_port_buffer *port_buffer,
				    u32 *max_buffer_size)
{
	int i, err, num_of_lossy_buffers = 0;
	int sz = MLX5_ST_SZ_BYTES(pbmc_reg);
	u32 lossless_buffers_max_sz;
	void *out;

	out = kzalloc(sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5e_port_query_pbmc(mdev, out);
	if (err)
		goto out;

	lossless_buffers_max_sz = MLX5_GET(pbmc_reg, out, port_buffer_size);

	for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
		if (port_buffer->buffer[i].lossy) {
			lossless_buffers_max_sz -= port_buffer->buffer[i].size;
			num_of_lossy_buffers++;
		}
	}
	if (num_of_lossy_buffers < MLX5E_MAX_NETWORK_BUFFER)
		*max_buffer_size = lossless_buffers_max_sz /
				   (MLX5E_MAX_NETWORK_BUFFER -
				    num_of_lossy_buffers);
	else
		*max_buffer_size = 0;

out:
	kfree(out);
	return err;
}

static int update_xoff_threshold(struct mlx5_core_dev *mdev,
				 struct mlx5e_port_buffer *port_buffer,
				 struct mlx5e_bufferx_reg *buffer,
				 u32 xoff, u32 xon, u32 lossless_buffer_size,
				 u16 max_mtu, u16 port_buff_cell_sz)
{
	u32 max_buffer_cell_size;
	int err;

	err = get_buffer_max_cell_size(mdev, port_buffer,
				       &max_buffer_cell_size);
	if (err)
		return err;

	if (buffer->lossy) {
		buffer->xoff = 0;
		buffer->xon  = 0;
		return 0;
	}

	/* Validate that the existing buffer size is sufficient for lossless operation */
	if (buffer->size < (xoff + max_mtu + port_buff_cell_sz)) {
		pr_err("buffer size %d is not enough for lossless buffer\n",
		       buffer->size);
		return -ENOMEM;
	}

	if (lossless_buffer_size > max_buffer_cell_size * port_buff_cell_sz) {
		lossless_buffer_size = max_buffer_cell_size;
		xoff = lossless_buffer_size / 2;
		xon = xoff > (max_mtu / 2) ? (xoff - (max_mtu * 2)) : 0;
	}

	buffer->xoff = xoff;
	buffer->xon = xon;
	buffer->size = lossless_buffer_size;

	return 0;
}

static int update_xoffs_threshold(struct mlx5_core_dev *mdev,
	struct mlx5e_port_buffer *port_buffer,
	u32 xoff, u32 xon, u32 lossless_buffer_size,
	u16 max_mtu, u16 port_buff_cell_sz)
{
	int i, err;

	for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
		err = update_xoff_threshold(mdev, port_buffer,
					    &port_buffer->buffer[i],
					    xoff, xon, lossless_buffer_size,
					    max_mtu, port_buff_cell_sz);
		if (err)
			return err;
	}

	return 0;
}

/**
 *	update_buffer_lossy	- Update buffer configuration based on pfc
 *	@mdev: port function core device
 *	@max_mtu: netdev's max_mtu
 *	@pfc_en: <input> current pfc configuration
 *	@buffer: <input> current prio to buffer mapping
 *	@xoff:   <input> xoff value
 *	@xon:    <input> xon value
 *	@port_buff_sz: <input> port buffer size
 *	@port_buff_cell_sz: <input> port buffer cell_size
 *	@port_buffer: <output> port receive buffer configuration
 *	@change: <output>
 *
 *	Update buffer configuration based on pfc configuration and
 *	priority to buffer mapping.
 *	Buffer's lossy bit is changed to:
 *		lossless if there is at least one PFC enabled priority
 *		mapped to this buffer lossy if all priorities mapped to
 *		this buffer are PFC disabled
 *
 *	@return: 0 if no error,
 *	sets change to true if buffer configuration was modified.
 */
static int update_buffer_lossy(struct mlx5_core_dev *mdev,
			       u16 max_mtu, u8 pfc_en, u8 *buffer,
			       u32 xoff, u32 xon, u32 port_buff_sz,
			       u16 port_buff_cell_sz,
			       struct mlx5e_port_buffer *port_buffer,
			       bool *change)
{
	bool changed = false;
	u8 lossy_count;
	u8 prio_count;
	u8 lossy;
	int prio;
	int err;
	int i;

	for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
		prio_count = 0;
		lossy_count = 0;

		for (prio = 0; prio < MLX5E_MAX_PRIORITY; prio++) {
			if (buffer[prio] != i)
				continue;

			prio_count++;
			lossy_count += !(pfc_en & (1 << prio));
		}

		if (lossy_count == prio_count)
			lossy = 1;
		else /* lossy_count < prio_count */
			lossy = 0;

		if (lossy != port_buffer->buffer[i].lossy) {
			port_buffer->buffer[i].lossy = lossy;
			changed = true;
		}
	}

	if (changed) {
		err = update_xoffs_threshold(mdev, port_buffer, xoff, xon,
					    port_buff_sz, max_mtu,
					    port_buff_cell_sz);
		if (err)
			return err;

		err = port_update_pool_cfg(mdev, port_buffer);
		if (err)
			return err;

		*change = true;
	}

	return 0;
}

static int fill_pfc_en(struct mlx5_core_dev *mdev, u8 *pfc_en)
{
	u32 g_rx_pause, g_tx_pause;
	int err;

	err = mlx5_query_port_pause(mdev, &g_rx_pause, &g_tx_pause);
	if (err)
		return err;

	/* If global pause enabled, set all active buffers to lossless.
	 * Otherwise, check PFC setting.
	 */
	if (g_rx_pause || g_tx_pause)
		*pfc_en = 0xff;
	else
		err = mlx5_query_port_pfc(mdev, pfc_en, NULL);

	return err;
}

#define MINIMUM_MAX_MTU 9216
int mlx5e_port_manual_buffer_config(struct mlx5e_priv *priv,
				    u32 change, struct ieee_pfc *pfc,
				    u32 *buffer_size, u8 *prio2buffer)
{
	u32 xoff, xon, lossless_buffer_size, min_buffer_size;
	u16 port_buff_cell_sz = priv->dcbx.port_buff_cell_sz;
	struct net_device *netdev = priv->netdev;
	struct mlx5e_port_buffer port_buffer;
	bool update_prio2buffer = false;
	u8 buffer[MLX5E_MAX_PRIORITY];
	bool update_buffer = false;
	u32 total_used = 0;
	u8 curr_pfc_en;
	u16 max_mtu;
	int err;
	int i;

	netdev_dbg(netdev, "%s: change=%x\n", __func__, change);
	mlx5_query_port_oper_mtu(priv->mdev, &max_mtu, 1);

	err = mlx5e_calculate_buf_sz_and_thresholds(priv, &xoff, &xon, max_mtu,
						    &lossless_buffer_size);
	if (err)
		return err;

	min_buffer_size = xoff + max_mtu + port_buff_cell_sz;

	err = mlx5e_port_query_buffer(priv, &port_buffer);
	if (err)
		return err;

	if (change & MLX5E_PORT_BUFFER_CABLE_LEN) {
		update_buffer = true;
		err = update_xoffs_threshold(priv->mdev, &port_buffer, xoff, xon,
					    lossless_buffer_size, max_mtu,
					    port_buff_cell_sz);
		if (err)
			return err;
	}

	if (change & MLX5E_PORT_BUFFER_PFC) {
		netdev_dbg(netdev, "%s: requested PFC per priority bitmask: 0x%x\n",
			   __func__, pfc->pfc_en);
		err = mlx5e_port_query_priority2buffer(priv->mdev, buffer);
		if (err)
			return err;

		err = update_buffer_lossy(priv->mdev, max_mtu, pfc->pfc_en,
					  buffer, xoff, xon,
					  lossless_buffer_size,
					  port_buff_cell_sz,  &port_buffer,
					  &update_buffer);
		if (err)
			return err;
	}

	if (change & MLX5E_PORT_BUFFER_PRIO2BUFFER) {
		update_prio2buffer = true;
		for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++)
			netdev_dbg(priv->netdev, "%s: requested to map prio[%d] to buffer %d\n",
				   __func__, i, prio2buffer[i]);

		err = fill_pfc_en(priv->mdev, &curr_pfc_en);
		if (err)
			return err;

		err = update_buffer_lossy(priv->mdev, max_mtu, curr_pfc_en,
					  prio2buffer, xoff, xon,
					  lossless_buffer_size,
					  port_buff_cell_sz, &port_buffer,
					  &update_buffer);
		if (err)
			return err;
	}

	if (change & MLX5E_PORT_BUFFER_SIZE) {
		for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
			netdev_dbg(priv->netdev, "%s: buffer[%d]=%d\n", __func__, i, buffer_size[i]);
			if (!port_buffer.buffer[i].lossy && !buffer_size[i]) {
				netdev_dbg(priv->netdev, "%s: lossless buffer[%d] size cannot be zero\n",
					   __func__, i);
				return -EINVAL;
			}

			if (!port_buffer.buffer[i].lossy &&
			    buffer_size[i] < min_buffer_size) {
				pr_err("buffer_size[%d]=%d is not enough for lossless buffer, minimun buffer size: %d\n",
				       i, buffer_size[i], min_buffer_size);
				return -ENOMEM;
			}

			total_used += buffer_size[i];
		}

		netdev_dbg(priv->netdev, "%s: total buffer requested=%d\n", __func__, total_used);

		if (total_used > port_buffer.headroom_size &&
		    (total_used - port_buffer.headroom_size) >
			    port_buffer.spare_buffer_size)
			return -EINVAL;

		update_buffer = true;
		for (i = 0; i < MLX5E_MAX_NETWORK_BUFFER; i++) {
			err = update_xoff_threshold(priv->mdev, &port_buffer,
						    &port_buffer.buffer[i],
						    xoff, xon, buffer_size[i],
						    max_mtu, port_buff_cell_sz);
			if (err)
				return err;
		}
	}

	/* Need to update buffer configuration if xoff value is changed */
	if (!update_buffer && xoff != priv->dcbx.xoff) {
		update_buffer = true;
		err = update_xoffs_threshold(priv->mdev, &port_buffer, xoff, xon,
					    lossless_buffer_size,
					    max_mtu, port_buff_cell_sz);
		if (err)
			return err;
	}

	/* Apply the settings */
	if (update_buffer) {
		err = port_set_buffer(priv, &port_buffer);
		if (err)
			return err;
	}

	priv->dcbx.xoff = xoff;

	if (update_prio2buffer)
		err = mlx5e_port_set_priority2buffer(priv->mdev, prio2buffer);

	return err;
}
