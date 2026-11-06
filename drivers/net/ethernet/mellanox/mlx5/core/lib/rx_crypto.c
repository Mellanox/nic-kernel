// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include "lib/rx_crypto.h"
#include "mlx5_core.h"
#include "fs_core.h"

/* RX crypto dispatch table
 *
 * The first table of the RX_CRYPTO namespace, shared by all RX crypto
 * protocols. A protocol takes a reference while it is enabled and adds an
 * entry rule steering its traffic into its own tables, which it must remove
 * before dropping the reference. Packets matching no entry rule miss the
 * table and continue to the next namespace.
 */

#define MLX5_RX_CRYPTO_DISPATCH_MAX_FTE 8

struct mlx5_flow_table *mlx5_rx_crypto_ft_get(struct mlx5_core_dev *mdev)
{
	struct mlx5_rx_crypto *rx_crypto = &mdev->priv.steering->rx_crypto;
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_namespace *ns;
	struct mlx5_flow_table *ft;

	mutex_lock(&rx_crypto->lock);
	if (rx_crypto->refcnt) {
		ft = rx_crypto->ft;
		goto get;
	}

	ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_RX_CRYPTO);
	if (!ns) {
		ft = ERR_PTR(-EOPNOTSUPP);
		goto out;
	}

	ft_attr.max_fte = MLX5_RX_CRYPTO_DISPATCH_MAX_FTE;
	ft_attr.level = MLX5_RX_CRYPTO_DISPATCH_LEVEL;
	ft = mlx5_create_auto_grouped_flow_table(ns, &ft_attr);
	if (IS_ERR(ft)) {
		mlx5_core_err(mdev,
			      "Failed to create RX crypto dispatch table, err %ld\n",
			      PTR_ERR(ft));
		goto out;
	}
	rx_crypto->ft = ft;
get:
	rx_crypto->refcnt++;
out:
	mutex_unlock(&rx_crypto->lock);
	return ft;
}

void mlx5_rx_crypto_ft_put(struct mlx5_core_dev *mdev)
{
	struct mlx5_rx_crypto *rx_crypto = &mdev->priv.steering->rx_crypto;

	mutex_lock(&rx_crypto->lock);
	if (WARN_ON(!rx_crypto->refcnt))
		goto out;
	if (--rx_crypto->refcnt)
		goto out;

	mlx5_destroy_flow_table(rx_crypto->ft);
	rx_crypto->ft = NULL;
out:
	mutex_unlock(&rx_crypto->lock);
}
