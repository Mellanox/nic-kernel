/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_LIB_RX_CRYPTO_H__
#define __MLX5_LIB_RX_CRYPTO_H__

#include <linux/mlx5/driver.h>
#include <linux/mlx5/fs.h>

/* Levels inside the RX_CRYPTO namespace. The shared dispatch table is first;
 * protocols place their own tables from MLX5_RX_CRYPTO_PROTO_LEVEL on.
 */
#define MLX5_RX_CRYPTO_DISPATCH_LEVEL 0
#define MLX5_RX_CRYPTO_PROTO_LEVEL 1

struct mlx5_flow_table *mlx5_rx_crypto_ft_get(struct mlx5_core_dev *mdev);
void mlx5_rx_crypto_ft_put(struct mlx5_core_dev *mdev);

#endif /* __MLX5_LIB_RX_CRYPTO_H__ */
